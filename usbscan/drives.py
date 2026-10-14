from __future__ import annotations

import psutil

REMOVABLE_MOUNT_PREFIXES = ("/media/", "/run/media/", "/Volumes/", "/mnt/")


def list_removable_mount_points() -> list[str]:
    mount_points = []
    for partition in psutil.disk_partitions(all=False):
        is_flagged_removable = "removable" in partition.opts.lower()
        is_under_removable_prefix = partition.mountpoint.startswith(REMOVABLE_MOUNT_PREFIXES)
        if is_flagged_removable or is_under_removable_prefix:
            mount_points.append(partition.mountpoint)
    return mount_points
