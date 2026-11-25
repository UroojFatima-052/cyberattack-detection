"""
Merge Sort

Used in this project to:
  1. sort the log rows by IP address, so all rows of one IP come together
  2. sort the blacklist once, so Binary Search can be used on it

Time complexity : O(n log n) in best, average and worst case
Extra space     : O(n) for the temporary lists made while merging
Stable          : yes (equal items keep their original order)
"""


def merge_sort(items, key=lambda item: item):
    """Return a new list with the items sorted in ascending order.

    key tells merge sort WHAT to compare.
    For the blacklist (a list of IP strings) we compare the IP itself.
    For log rows (dictionaries) we pass key=lambda row: row["IP Address"].
    """
    # Base case: 0 or 1 item is already sorted
    if len(items) <= 1:
        return items

    # Divide: split into two halves (odd count -> extra item goes right)
    mid = len(items) // 2
    left = merge_sort(items[:mid], key)
    right = merge_sort(items[mid:], key)

    # Combine: merge the two sorted halves
    return merge(left, right, key)


def merge(left, right, key):
    """Merge two sorted lists into one sorted list."""
    result = []
    i = 0  # pointer into left
    j = 0  # pointer into right

    # Compare the front of each list and take the smaller one
    while i < len(left) and j < len(right):
        if key(left[i]) <= key(right[j]):  # <= keeps the sort stable
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1

    # One list ran out: copy whatever is left in the other one
    while i < len(left):
        result.append(left[i])
        i += 1
    while j < len(right):
        result.append(right[j])
        j += 1

    return result
