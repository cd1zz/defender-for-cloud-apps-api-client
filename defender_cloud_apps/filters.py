"""
Filter builder utilities for Microsoft Defender for Cloud Apps API.

This module provides a fluent interface for building complex filter queries.
"""

from typing import Any, Dict, List, Union


class FilterBuilder:
    """
    A fluent interface for building API filter queries.

    The FilterBuilder makes it easier to construct complex filter criteria
    without manually managing nested dictionaries.

    Example:
        >>> filters = (FilterBuilder()
        ...     .equals("user.username", "admin@example.com")
        ...     .greater_than_or_equal("date", 1609459200000)
        ...     .contains("activity.eventActionType", "login")
        ...     .build())
    """

    def __init__(self):
        """Initialize an empty filter builder."""
        self._filters: Dict[str, Any] = {}

    def equals(self, field: str, value: Any) -> "FilterBuilder":
        """
        Add an equality filter (eq operator).

        Args:
            field: The field name to filter on
            value: The value to match

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().equals("severity", 2)
        """
        self._filters[field] = {"eq": value}
        return self

    def not_equals(self, field: str, value: Any) -> "FilterBuilder":
        """
        Add a not-equals filter (neq operator).

        Args:
            field: The field name to filter on
            value: The value to exclude

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().not_equals("status", "closed")
        """
        self._filters[field] = {"neq": value}
        return self

    def contains(self, field: str, value: str) -> "FilterBuilder":
        """
        Add a contains filter for text fields.

        Args:
            field: The field name to filter on
            value: The substring to search for

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().contains("filename", "report")
        """
        self._filters[field] = {"contains": value}
        return self

    def startswith(self, field: str, value: str) -> "FilterBuilder":
        """
        Add a starts-with filter for text fields.

        Args:
            field: The field name to filter on
            value: The prefix to match

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().startswith("user.username", "admin")
        """
        self._filters[field] = {"startswith": value}
        return self

    def endswith(self, field: str, value: str) -> "FilterBuilder":
        """
        Add an ends-with filter for text fields.

        Args:
            field: The field name to filter on
            value: The suffix to match

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().endswith("extension", "pdf")
        """
        self._filters[field] = {"endswith": value}
        return self

    def greater_than(self, field: str, value: Union[int, float]) -> "FilterBuilder":
        """
        Add a greater-than filter (gt operator).

        Args:
            field: The field name to filter on
            value: The minimum value (exclusive)

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().greater_than("severity", 1)
        """
        self._filters[field] = {"gt": value}
        return self

    def greater_than_or_equal(
        self, field: str, value: Union[int, float]
    ) -> "FilterBuilder":
        """
        Add a greater-than-or-equal filter (gte operator).

        Args:
            field: The field name to filter on
            value: The minimum value (inclusive)

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().greater_than_or_equal("date", 1609459200000)
        """
        self._filters[field] = {"gte": value}
        return self

    def less_than(self, field: str, value: Union[int, float]) -> "FilterBuilder":
        """
        Add a less-than filter (lt operator).

        Args:
            field: The field name to filter on
            value: The maximum value (exclusive)

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().less_than("severity", 2)
        """
        self._filters[field] = {"lt": value}
        return self

    def less_than_or_equal(
        self, field: str, value: Union[int, float]
    ) -> "FilterBuilder":
        """
        Add a less-than-or-equal filter (lte operator).

        Args:
            field: The field name to filter on
            value: The maximum value (inclusive)

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().less_than_or_equal("date", 1609459200000)
        """
        self._filters[field] = {"lte": value}
        return self

    def date_range(
        self, field: str, start: int, end: int
    ) -> "FilterBuilder":
        """
        Add a date range filter.

        Args:
            field: The field name to filter on (typically "date" or timestamp field)
            start: Start timestamp in milliseconds since epoch
            end: End timestamp in milliseconds since epoch

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().date_range("date", 1609459200000, 1612137600000)
        """
        self._filters[field] = {"range": {"start": start, "end": end}}
        return self

    def is_set(self, field: str) -> "FilterBuilder":
        """
        Add a filter for fields that have a value set (isset operator).

        Args:
            field: The field name to check

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().is_set("policy")
        """
        self._filters[field] = {"isset": True}
        return self

    def is_not_set(self, field: str) -> "FilterBuilder":
        """
        Add a filter for fields that do not have a value (isnotset operator).

        Args:
            field: The field name to check

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().is_not_set("policy")
        """
        self._filters[field] = {"isnotset": True}
        return self

    def in_last_n_days(self, field: str, days: int) -> "FilterBuilder":
        """
        Add a filter for dates within the last N days (gte_ndays operator).

        Args:
            field: The field name to filter on
            days: Number of days to look back

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().in_last_n_days("date", 7)
        """
        self._filters[field] = {"gte_ndays": days}
        return self

    def not_in_last_n_days(self, field: str, days: int) -> "FilterBuilder":
        """
        Add a filter for dates not within the last N days (lte_ndays operator).

        Args:
            field: The field name to filter on
            days: Number of days

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().not_in_last_n_days("date", 30)
        """
        self._filters[field] = {"lte_ndays": days}
        return self

    def custom(self, field: str, operator: str, value: Any) -> "FilterBuilder":
        """
        Add a custom filter with any operator.

        Use this for advanced filtering or operators not covered by convenience methods.

        Args:
            field: The field name to filter on
            operator: The filter operator (eq, neq, gt, gte, lt, lte, etc.)
            value: The filter value

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().custom("custom_field", "custom_op", "value")
        """
        self._filters[field] = {operator: value}
        return self

    def build(self) -> Dict[str, Any]:
        """
        Build and return the filter dictionary.

        Returns:
            Dictionary of filters suitable for API requests

        Example:
            >>> filters = FilterBuilder().equals("severity", 2).build()
        """
        return self._filters

    def clear(self) -> "FilterBuilder":
        """
        Clear all filters.

        Returns:
            Self for method chaining

        Example:
            >>> fb = FilterBuilder().equals("x", 1).clear().equals("y", 2)
        """
        self._filters = {}
        return self


class TimeHelper:
    """
    Helper class for working with timestamps in the API.

    The API uses milliseconds since epoch (Unix timestamp * 1000).
    """

    @staticmethod
    def now_ms() -> int:
        """
        Get current time in milliseconds since epoch.

        Returns:
            Current timestamp in milliseconds

        Example:
            >>> current_time = TimeHelper.now_ms()
        """
        import time
        return int(time.time() * 1000)

    @staticmethod
    def days_ago_ms(days: int) -> int:
        """
        Get timestamp for N days ago in milliseconds.

        Args:
            days: Number of days to go back

        Returns:
            Timestamp in milliseconds

        Example:
            >>> week_ago = TimeHelper.days_ago_ms(7)
        """
        import time
        days_in_seconds = days * 24 * 60 * 60
        return int((time.time() - days_in_seconds) * 1000)

    @staticmethod
    def hours_ago_ms(hours: int) -> int:
        """
        Get timestamp for N hours ago in milliseconds.

        Args:
            hours: Number of hours to go back

        Returns:
            Timestamp in milliseconds

        Example:
            >>> six_hours_ago = TimeHelper.hours_ago_ms(6)
        """
        import time
        hours_in_seconds = hours * 60 * 60
        return int((time.time() - hours_in_seconds) * 1000)

    @staticmethod
    def from_datetime(dt) -> int:
        """
        Convert a datetime object to milliseconds since epoch.

        Args:
            dt: datetime object

        Returns:
            Timestamp in milliseconds

        Example:
            >>> from datetime import datetime
            >>> dt = datetime(2021, 1, 1)
            >>> timestamp = TimeHelper.from_datetime(dt)
        """
        return int(dt.timestamp() * 1000)

    @staticmethod
    def to_datetime(timestamp_ms: int):
        """
        Convert milliseconds since epoch to datetime object.

        Args:
            timestamp_ms: Timestamp in milliseconds

        Returns:
            datetime object

        Example:
            >>> dt = TimeHelper.to_datetime(1609459200000)
        """
        from datetime import datetime
        return datetime.fromtimestamp(timestamp_ms / 1000)
