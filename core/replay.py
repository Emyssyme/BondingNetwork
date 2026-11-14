class ReplayWindow:
    """Tracks accepted packet sequence numbers with a bounded sliding window."""

    def __init__(self, size: int = 128):
        if size <= 0:
            raise ValueError("Replay window size must be positive")
        self.size = size
        self._mask = (1 << size) - 1
        self._highest = -1
        self._bitmap = 0

    def accept(self, sequence: int) -> bool:
        if sequence < 0:
            return False
        if self._highest < 0:
            self._highest = sequence
            self._bitmap = 1
            return True
        if sequence > self._highest:
            shift = sequence - self._highest
            self._bitmap = (
                1 if shift >= self.size
                else ((self._bitmap << shift) | 1) & self._mask
            )
            self._highest = sequence
            return True

        offset = self._highest - sequence
        if offset >= self.size or self._bitmap & (1 << offset):
            return False
        self._bitmap |= 1 << offset
        return True
