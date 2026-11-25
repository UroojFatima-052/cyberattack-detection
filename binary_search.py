"""
Binary Search

Used in this project to check whether an IP address is on the blacklist.
The blacklist must be SORTED first (we sort it once with Merge Sort).

Time complexity : O(1) best case, O(log m) average and worst case,
                  where m is the number of IPs in the blacklist
Extra space     : O(1)
"""


def binary_search(sorted_list, target):
    """Return the index of target in sorted_list, or -1 if it is not there."""
    low = 0
    high = len(sorted_list) - 1

    while low <= high:
        mid = (low + high) // 2

        if sorted_list[mid] == target:
            return mid              # found
        elif target > sorted_list[mid]:
            low = mid + 1           # target is in the right half
        else:
            high = mid - 1          # target is in the left half

    return -1                       # low > high: range is empty, not found
