# Standard Libraries
from itertools import islice
import os
import socket
import threading
from typing import (
    Iterable,
    Iterator,
    Sequence,
    TypeVar,
)


def is_headless() -> bool:
    """Check if IDA is running in headless/batch mode.

    Checks the MCPYIDA_HEADLESS env-var first so that headless.py can assert
    headless mode even when idalib doesn't set the batch flag.
    """
    if os.environ.get('MCPYIDA_HEADLESS'):
        return True
    try:
        import ida_kernwin

        # Check batch mode flag - non-zero when running with -A flag
        if hasattr(ida_kernwin, 'cvar') and hasattr(ida_kernwin.cvar, 'batch'):
            return ida_kernwin.cvar.batch != 0
        # Alternative: check if UI message system is initialized
        return not ida_kernwin.is_msg_inited()
    except Exception:
        return True  # Assume headless if we can't detect


class AtomicCounter:
    """
    A thread-safe integer counter that supports atomic increment, decrement,
    comparison with integers or other AtomicCounter instances, and += / -= operations.
    """

    def __init__(self, initial: int = 0) -> None:
        self._value: int = initial
        self._lock: threading.RLock = threading.RLock()

    def increment(self) -> int:
        """
        Atomically increments the counter by 1.
        Returns the new value.
        """
        with self._lock:
            self._value += 1
            return self._value

    def decrement(self) -> int:
        """
        Atomically decrements the counter by 1.
        Returns the new value.
        """
        with self._lock:
            self._value -= 1
            return self._value

    def value(self) -> int:
        """
        Returns the current value of the counter.
        """
        with self._lock:
            return self._value

    def reset(self) -> None:
        with self._lock:
            self._value = 0

    # In-place addition: counter += int
    def __iadd__(self, other: int) -> 'AtomicCounter':
        with self._lock:
            self._value += other
        return self

    # In-place subtraction: counter -= int
    def __isub__(self, other: int) -> 'AtomicCounter':
        with self._lock:
            self._value -= other
        return self

    # Equality comparison: counter == int or counter == AtomicCounter
    def __eq__(self, other: object) -> bool:
        if isinstance(other, AtomicCounter):
            return self.value() == other.value()
        elif isinstance(other, int):
            return self.value() == other
        return NotImplemented

    # Inequality comparison: counter != other
    def __ne__(self, other: object) -> bool:
        return not self == other

    def __lt__(self, other: object) -> bool:
        if isinstance(other, (AtomicCounter, int)):
            return self.value() < (
                other.value() if isinstance(other, AtomicCounter) else other
            )
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, (AtomicCounter, int)):
            return self.value() <= (
                other.value() if isinstance(other, AtomicCounter) else other
            )
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, (AtomicCounter, int)):
            return self.value() > (
                other.value() if isinstance(other, AtomicCounter) else other
            )
        return NotImplemented

    def __ge__(self, other: object) -> bool:
        if isinstance(other, (AtomicCounter, int)):
            return self.value() >= (
                other.value() if isinstance(other, AtomicCounter) else other
            )
        return NotImplemented

    def __repr__(self) -> str:
        return f'AtomicCounter({self.value()})'


T = TypeVar('T')


def paginate(
    iterable: Iterable[T], offset: int = 0, limit: int | None = None
) -> Iterator[T]:
    """
    Lazily paginates any iterable or iterator.

    Args:
        iterable: Any iterable or iterator to paginate.
        offset: Number of items to skip from the start (default: 0).
        limit: Maximum number of items to yield after the index (default: -1 for no limit).

    Returns:
        An iterator over the paginated items.
    """
    # Convert to iterator (if it isn't already)
    # Skip 'index' items
    return islice(iter(iterable), offset, offset + limit if limit is not None else None)


def paginate_with_total(
    items: Iterable[T], offset: int = 0, limit: int | None = None
) -> tuple[list[T], int, int, int]:
    """
    Return a slice of items along with total count and [start, end) indices.
    If `items` isn't a Sequence, materialize it.
    """
    if not isinstance(items, Sequence):
        items = list(items)
    total = len(items)

    start = max(0, offset)
    if limit is None or limit < 0:
        stop = total
    else:
        stop = min(start + limit, total)

    return list(items[start:stop]), total, start, stop  # stop is exclusive


def is_port_available(port, host='127.0.0.1'):
    """Returns True if the TCP port is available on the given host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def find_next_available_port(start_port, end_port=None, host='127.0.0.1'):
    """
    Finds the next available TCP port starting from start_port.

    Parameters:
        start_port (int): The starting port to check.
        end_port (int or None): Optional ending port (inclusive). If None, checks up to 65535.
        host (str): The host/interface to bind to. Default is '127.0.0.1'.

    Returns:
        int: The first available port.

    Raises:
        RuntimeError: If no port is available in the range.
    """
    max_port = end_port if end_port is not None else 65535
    for port in range(start_port, max_port + 1):
        if is_port_available(port, host):
            return port
    raise RuntimeError(f'No available port found in range {start_port}-{max_port}')
