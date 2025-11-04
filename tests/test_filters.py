"""Tests for the FilterBuilder utility."""

import pytest
from defender_cloud_apps import FilterBuilder


class TestFilterBuilder:
    """Test FilterBuilder class."""

    def test_equals_filter(self):
        """Test equals filter."""
        filters = FilterBuilder().equals("field", "value").build()
        assert filters == {"field": {"eq": "value"}}

    def test_not_equals_filter(self):
        """Test not equals filter."""
        filters = FilterBuilder().not_equals("field", "value").build()
        assert filters == {"field": {"neq": "value"}}

    def test_greater_than_filter(self):
        """Test greater than filter."""
        filters = FilterBuilder().greater_than("field", 10).build()
        assert filters == {"field": {"gt": 10}}

    def test_greater_than_or_equal_filter(self):
        """Test greater than or equal filter."""
        filters = FilterBuilder().greater_than_or_equal("field", 10).build()
        assert filters == {"field": {"gte": 10}}

    def test_less_than_filter(self):
        """Test less than filter."""
        filters = FilterBuilder().less_than("field", 10).build()
        assert filters == {"field": {"lt": 10}}

    def test_less_than_or_equal_filter(self):
        """Test less than or equal filter."""
        filters = FilterBuilder().less_than_or_equal("field", 10).build()
        assert filters == {"field": {"lte": 10}}

    def test_contains_filter(self):
        """Test contains filter."""
        filters = FilterBuilder().contains("field", "value").build()
        assert filters == {"field": {"contains": "value"}}

    def test_starts_with_filter(self):
        """Test starts with filter."""
        filters = FilterBuilder().startswith("field", "value").build()
        assert filters == {"field": {"startswith": "value"}}

    def test_ends_with_filter(self):
        """Test ends with filter."""
        filters = FilterBuilder().endswith("field", "value").build()
        assert filters == {"field": {"endswith": "value"}}

    def test_multiple_filters(self):
        """Test chaining multiple filters."""
        filters = (FilterBuilder()
                  .equals("field1", "value1")
                  .greater_than("field2", 10)
                  .contains("field3", "search")
                  .build())

        assert filters == {
            "field1": {"eq": "value1"},
            "field2": {"gt": 10},
            "field3": {"contains": "search"}
        }

    def test_range_filter(self):
        """Test range filter with date_range method."""
        filters = FilterBuilder().date_range("timestamp", 1609459200000, 1612137600000).build()

        assert "timestamp" in filters
        assert filters["timestamp"]["range"]["start"] == 1609459200000
        assert filters["timestamp"]["range"]["end"] == 1612137600000

    def test_empty_builder(self):
        """Test building with no filters."""
        filters = FilterBuilder().build()
        assert filters == {}

    def test_fluent_interface(self):
        """Test that methods return self for chaining."""
        builder = FilterBuilder()
        result = builder.equals("field", "value")
        assert result is builder
