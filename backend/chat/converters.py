"""Bounded URL converters for identifiers that reach persistence lookups."""


class PositiveBigIntConverter:
    regex = r'[0-9]{1,19}'
    maximum = (1 << 63) - 1

    def to_python(self, value):
        parsed = int(value)
        if not 1 <= parsed <= self.maximum:
            raise ValueError
        return parsed

    def to_url(self, value):
        parsed = int(value)
        if not 1 <= parsed <= self.maximum:
            raise ValueError
        return str(parsed)


class SessionHandleConverter:
    regex = r'[0-9a-f]{64}'

    def to_python(self, value):
        return value

    def to_url(self, value):
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError
        if any(character not in '0123456789abcdef' for character in value):
            raise ValueError
        return value
