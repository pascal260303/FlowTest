/**
 * @file
 * @author Samuel Luptak <xluptas00@stud.fit.vutbr.cz>
 * @brief Dpdk queue implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "dpdkQueue.hpp"
#include "packet.hpp"
#include <cinttypes>
#include <cstdint>
#include <iostream>
#include <memory>
#include <queue>
#include <rte_build_config.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <string>
#include <vector>

namespace replay {

DpdkQueue::DpdkQueue(DpdkQueueParams& params)
	: _burstSize(params.burstSize)
	, _poolSize(params.poolSize)
	, _MTUSize(params.MTUSize)
	, _queueId(params.queueId)
	, _ports(params.ports)
{
	int numOfPorts = _ports.size();
	if (numOfPorts != 1 && numOfPorts != 2) {
		_logger->error(
			"DpdkQueue initialized with wrong number of ports {} (only 1 or 2 allowed)",
			numOfPorts);
		throw std::runtime_error("DpdkQueue::DpdkQueue() has failed");
	}

	struct rte_mempool* pool;
	std::string poolName;

	poolName = "memPool" + std::to_string(_queueId);
	pool = rte_pktmbuf_pool_create(
		poolName.c_str(),
		_poolSize,
		0,
		0,
		RTE_PKTMBUF_HEADROOM + _MTUSize,
		DetermineSocket());

	if (pool == NULL) {
		_logger->error(
			"Pool allocation in DpdkQueue() has failed with rte_errno: {}",
			rte_strerror(rte_errno));
		throw std::runtime_error("DpdkQueue::DpdkQueue() has failed");
	}

	_pool.reset(pool);
	_mainMbuf = std::make_unique<struct rte_mbuf*[]>(_burstSize);

	for (int portCnt = 0; portCnt < 2; portCnt++) {
		DpdkQueueMbufs newMbuf {std::make_unique<struct rte_mbuf*[]>(_burstSize), 0};
		_mbufs.push_back(std::move(newMbuf));
	}
}

void DpdkQueue::GetBurst(PacketBuffer* burst, size_t burstSize)
{
	if (burstSize > _burstSize) {
		_logger->error(
			"Requested burstSize {} is bigger than maximum allowed {}",
			burstSize,
			_burstSize);
		throw std::runtime_error("DpdkQueue::GetBurst() has failed");
	}

	// Loop until you get the needed memory, with exponential backoff
	constexpr size_t MAX_RETRIES = 10000;  // ~10ms with rte_pause()
	constexpr size_t FLUSH_TRIGGER = 1000; // Trigger flush after 1000 retries
	size_t retries = 0;
	while (rte_pktmbuf_alloc_bulk(_pool.get(), _mainMbuf.get(), burstSize)) {
		rte_pause();
		if (++retries == FLUSH_TRIGGER) {
			// Pool might be exhausted, try to flush pending TX
			_logger->warn("Mempool allocation stalling, attempting to flush TX ring");
			Flush();
		}
		if (retries > MAX_RETRIES) {
			_logger->error(
				"Failed to allocate {} mbufs from pool after {} retries. Pool may be exhausted.",
				burstSize,
				MAX_RETRIES);
			throw std::runtime_error("DpdkQueue::GetBurst() timed out");
		}
	}

	for (size_t packetId = 0; packetId < burstSize; packetId++) {
		if (burst[packetId]._len > _MTUSize) {
			_logger->error(
				"Requested packet size ({} bytes) is greater than MTU",
				burst[packetId]._len);
			throw std::runtime_error("DpdkQueue::GetBurst() has failed");
		}

		burst[packetId]._data = reinterpret_cast<std::byte*>(
			rte_pktmbuf_append(_mainMbuf.get()[packetId], burst[packetId]._len));

		DpdkQueueMbufs& ifBuf = (burst[packetId]._info->outInterface == OutInterface::Interface0)
			? _mbufs[0]
			: _mbufs[1];
		ifBuf.mbuf[ifBuf.pktsToSend++] = _mainMbuf[packetId];
	}
}

void DpdkQueue::SendBurst(const PacketBuffer* buffer)
{
	(void) buffer;

	if (_ports.size() == 1) {
		size_t burstSize = _mbufs[0].pktsToSend + _mbufs[1].pktsToSend;
		DoBurst(_ports[0], burstSize, _mainMbuf.get());
	} else {
		DoBurst(_ports[0], _mbufs[0].pktsToSend, _mbufs[0].mbuf.get());
		DoBurst(_ports[1], _mbufs[1].pktsToSend, _mbufs[1].mbuf.get());
	}

	for (int i = 0; i < 2; i++) {
		_mbufs[i].pktsToSend = 0;
	}
}

void DpdkQueue::Flush()
{
	// Drain TX rings to free mbufs back to the pool
	// This is critical with RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE
	constexpr size_t MAX_DRAIN_ITERATIONS = 1000;
	
	for (size_t iter = 0; iter < MAX_DRAIN_ITERATIONS; iter++) {
		bool any_drained = false;
		
		// Call tx_burst with 0 packets to drain completions
		for (uint16_t port : _ports) {
			uint16_t drained = rte_eth_tx_burst(port, _queueId, nullptr, 0);
			if (drained > 0) {
				any_drained = true;
			}
		}
		
		// If nothing drained in last iteration, pool should be clearing
		if (!any_drained) {
			// Try one more time with a small delay
			for (int j = 0; j < 10000; j++) {
				rte_pause();
			}
			break;
		}
		
		// Small pause between iterations
		rte_pause();
	}
	
	_logger->debug("Flush() completed: attempting to drain TX descriptors");
}

void DpdkQueue::DoBurst(uint16_t port, size_t pktsToSend, struct rte_mbuf** mbuf)
{
	size_t sentCount {0};
	size_t confirmed;
	constexpr size_t TX_DRAIN_INTERVAL = 128; // Drain every N packets

	while (true) {
		// Before sending next batch, drain some completed TXs
		// This is critical with RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE
		if (sentCount > 0 && sentCount % TX_DRAIN_INTERVAL == 0) {
			// Call tx_burst with 0 packets to process TX completions
			rte_eth_tx_burst(port, _queueId, nullptr, 0);
		}
		
		confirmed = rte_eth_tx_burst(port, _queueId, mbuf + sentCount, pktsToSend - sentCount);
		sentCount += confirmed;

		if (sentCount == pktsToSend) {
			break;
		}

		rte_pause();
	}
	
	// Final drain to ensure completions are processed
	for (int i = 0; i < 10; i++) {
		rte_eth_tx_burst(port, _queueId, nullptr, 0);
		rte_pause();
	}

	for (unsigned packetId = 0; packetId < pktsToSend; packetId++) {
		_outputQueueStats.transmittedBytes += mbuf[packetId]->data_len;
	}
	_outputQueueStats.transmittedPackets += sentCount;
	_outputQueueStats.UpdateTime();
}

size_t DpdkQueue::GetMaxBurstSize() const noexcept
{
	return _burstSize;
}

int DpdkQueue::DetermineSocket()
{
	std::vector<int> sockets;
	sockets.reserve(_ports.size());

	for (uint16_t port : _ports) {
		sockets.push_back(rte_eth_dev_socket_id(port));
	}

	if (sockets.size() == 1 || sockets[0] == sockets[1]) {
		return sockets[0];
	} else {
		return SOCKET_ID_ANY;
	}
}

} // namespace replay
