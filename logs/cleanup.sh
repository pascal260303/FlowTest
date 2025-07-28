#!/bin/bash
# removes log dirs where only one test was run
# because those are considered tests that are not interesting anymore

# Root directory containing the timestamp folders
ROOT_DIR="."

# Loop through each main folder
for dir in "$ROOT_DIR"/*/*; do
    # Check if it exists and is a directory
    [ -d "$dir" ] || continue

    # Count the number of subdirectories (ignoring files)
    subdirs=($(find "$dir" -mindepth 1 -maxdepth 1 -type d))
    if [ ${#subdirs[@]} -le 1 ]; then
        # delete test type dirs
        rm -r "$dir"
    fi
    parent_dir=$(dirname $dir)
    subdirs=($(find "$parent_dir" -mindepth 1 -maxdepth 1 -type d))
    if [ ${#subdirs[@]} -eq 0 ]; then
        # delete parent folder
	rm "${parent_dir}/report.html"
        rmdir "${parent_dir}"
    fi
done

#
for dir in "${ROOT_DIR}"/*; do
    [ -d "${dir}" ] || continue

    subdirs=($(find "$dir" -mindepth 1 -maxdepth 1 -type d))
    if [ ${#subdirs[@]} -eq 0 ]; then
        # delete parent folder
        rm "${dir}/report.html"
        rmdir "${dir}"
    fi
done
