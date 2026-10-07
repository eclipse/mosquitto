""" """

from collections.abc import Mapping, Sequence
import dataclasses


class Matcher:
    def __init__(self):
        self.last_message = ""

    def __repr__(self):
        return f"{self.__class__.__name__}"

    def __call__(self, _):
        raise NotImplementedError()


class UnaryMatcher(Matcher):
    def __init__(self, expectation):
        Matcher.__init__(self)
        self._expectation = expectation

    def __call__(self, _):
        raise NotImplementedError()

    def __len__(self):
        return len(self._expectation)


class CountMatcher(Matcher):
    def __init__(self, expectation, expected_count):
        Matcher.__init__(self)
        self._expectation = expectation
        self._expected_count = expected_count

    def __call__(self, _):
        raise NotImplementedError()

    def __len__(self):
        return len(self._expectation * self._expected_count)


class And(Matcher):
    def __init__(self, *matchers):
        Matcher.__init__(self)
        self._matchers = [
            matcher if isinstance(matcher, Matcher) else RecursiveMatcher(matcher)
            for matcher in matchers
        ]

    def __call__(self, candidate):
        self.last_message = ""
        for matcher in self._matchers:
            if not matcher(candidate):
                self.last_message = matcher.last_message
                return False
        return True

    def __repr__(self):
        return " && ".join([str(m) for m in self._matchers])


class Or(Matcher):
    def __init__(self, *matchers):
        Matcher.__init__(self)
        self._matchers = [
            matcher if isinstance(matcher, Matcher) else RecursiveMatcher(matcher)
            for matcher in matchers
        ]

    def __call__(self, candidate):
        self.last_message = ""
        for matcher in self._matchers:
            if matcher(candidate):
                return True
            else:
                self.last_message += (
                    f"{' and ' if self.last_message else ''}{matcher.last_message}"
                )
        return False

    def __len__(self):
        first_len = len(self._matchers[0])
        assert all(len(lst) == first_len for lst in self._matchers[1:])
        return first_len


class Any(Matcher):
    def __call__(self, candidate):
        return True


class AnyOrder(UnaryMatcher):
    def __call__(self, candidate):
        candidate = list(candidate)
        for expected_element in self._expectation:
            removed, msg = self._remove_matching_element(candidate, expected_element)
            if not removed:
                self.last_message = f"Cannot find element {expected_element} in {candidate} due to {msg}"
                return False
        if len(candidate):
            self.last_message = f"Found additional elements {candidate}"
            return False
        return True

    def _remove_matching_element(self, candidate_list, expected_element):
        matcher = (
            expected_element
            if isinstance(expected_element, Matcher)
            else RecursiveMatcher(expected_element)
        )
        for candidate_element in candidate_list:
            if matcher(candidate_element):
                candidate_list.remove(candidate_element)
                return True, ""
        return False, matcher.last_message

    def __repr__(self):
        return f" = <any order> {self._expectation}"


class EqualTo(UnaryMatcher):
    def __call__(self, candidate):
        if candidate != self._expectation:
            self.last_message = (
                f"{candidate} (actual) != {self._expectation} (expected)"
            )
            return False
        return True

    def __repr__(self):
        return f" == {self._expectation}"


class GreaterEqual(UnaryMatcher):
    def __call__(self, candidate):
        if candidate < self._expectation:
            self.last_message = f"{candidate} < {self._expectation}"
            return False
        return True

    def __repr__(self):
        return f" >= {self._expectation}"


class GreaterThan(UnaryMatcher):
    def __call__(self, candidate):
        if candidate <= self._expectation:
            self.last_message = f"{candidate} > {self._expectation}"
            return False
        return True

    def __repr__(self):
        return f" > {self._expectation}"


class LowerEqual(UnaryMatcher):
    def __call__(self, candidate):
        if candidate > self._expectation:
            self.last_message = f"{candidate} > {self._expectation}"
            return False
        return True

    def __repr__(self):
        return f" <= {self._expectation}"


class LowerThan(UnaryMatcher):
    def __call__(self, candidate):
        if candidate >= self._expectation:
            self.last_message = f"{candidate} > {self._expectation}"
            return False
        return True

    def __repr__(self):
        return f" < {self._expectation}"


class Field(Matcher):
    def __init__(self, field_name, expectation):
        Matcher.__init__(self)
        self._field_name = field_name
        self._field_matcher = (
            expectation if isinstance(expectation, Matcher) else EqualTo(expectation)
        )

    def __call__(self, candidate):
        if dataclasses.is_dataclass(candidate):
            candidate = dataclasses.asdict(candidate)
        if not isinstance(candidate, Mapping):
            self.last_message = f"{candidate} is not a Mapping type"
            return False
        if not self._field_name in candidate:
            self.last_message = f"{candidate} does not contain field {self._field_name}"
            return False
        result = self._field_matcher(candidate[self._field_name])
        if not result:
            self.last_message = (
                f"{self._field_matcher.last_message} in field {self._field_name}"
            )
        return result

    def __repr__(self):
        return f"Field {self._field_name} {self._field_matcher}"


class FieldIni(Matcher):
    def __init__(self, field_name, expectation):
        Matcher.__init__(self)
        self._field_name = field_name
        self._field_matcher = (
            expectation if isinstance(expectation, Matcher) else EqualTo(expectation)
        )

    def __call__(self, candidate):
        if not isinstance(candidate, str):
            self.last_message = f"{candidate} is not of string type"
            return False
        if not self._field_name in candidate:
            self.last_message = f"{candidate} does not contain field {self._field_name}"
            return False
        value = [
            line.split(" ")[-1]
            for line in candidate.splitlines()
            if line.startswith(self._field_name)
        ]
        if len(value) > 1:
            self.last_message = f"Found multiple values for {self._field_name}"
            return False
        result = self._field_matcher(value[-1])
        if not result:
            self.last_message = (
                f"{self._field_matcher.last_message} in field {self._field_name}"
            )
        return result

    def __repr__(self):
        return f"Field {self._field_name} {self._field_matcher}"


class RecursiveMatcher(UnaryMatcher):
    def __call__(self, candidate):
        result, self.last_message, path = self._recursive_match(
            candidate, self._expectation
        )
        self.last_message += f" at {path}"
        return result

    def _recursive_match(self, candidate, expectation):
        if expectation is None:
            return candidate is None, f"{candidate} is not None", ""

        if isinstance(expectation, RecursiveMatcher):
            return expectation._recursive_match(candidate, expectation._expectation)

        if isinstance(expectation, Matcher):
            result = expectation(candidate)
            if not result:
                return False, expectation.last_message, ""
            return True, "", ""

        if isinstance(expectation, Mapping):
            if not isinstance(candidate, Mapping):
                return False, f"{candidate} is not a Mapping type", ""
            return self._match_mapping(candidate, expectation)

        if isinstance(expectation, str):
            if not isinstance(candidate, str):
                return False, f"{candidate} is not a String", ""
            return (
                candidate == expectation,
                f"{candidate} (actual) != {expectation} (expected)",
                "",
            )

        if isinstance(expectation, Sequence):
            if not isinstance(candidate, Sequence):
                return False, f"{candidate} is not a Sequence", ""
            return self._match_sequence(candidate, expectation)

        return (
            candidate == expectation,
            f"{candidate} (actual) != {expectation} (expected)",
            "",
        )

    def _match_mapping(self, candidate, expectation):
        for key, value in expectation.items():
            if not key in candidate:
                return False, f"'{key}' not found in Mapping", ""
            result, message, path = self._recursive_match(candidate.get(key), value)
            if not result:
                return False, f"{message}", f".{key}{path}"
        return self._check_additional_mapping_entries(candidate, expectation)

    def _check_additional_mapping_entries(self, candidate, expectation):
        if len(candidate) != len(expectation):
            left_overs = (
                set(candidate.keys()) - set(expectation.keys())
                if len(expectation) > 0
                else candidate
            )
            return False, f"Additional elements found: {left_overs}", ""
        return True, "", ""

    def _match_sequence(self, candidate, expectation):
        if len(candidate) != len(expectation):
            return (
                False,
                f"sequence of different size. expected {len(expectation)} elements, but got {len(candidate)}",
                "",
            )
        for index in range(len(expectation)):
            result, message, path = self._recursive_match(
                candidate[index], expectation[index]
            )
            if not result:
                return (
                    False,
                    f"element does not match due to {message}",
                    f"[{index}]{path}",
                )
            if len(candidate) > len(expectation):
                return (
                    False,
                    f"Additional elements found: {candidate[len(expectation):]}",
                    "[{len(expectation)-1}:{len(candidate)-1}]",
                )
        return True, "", ""

    def __repr__(self):
        if hasattr(self._expectation, "__repr__"):
            return str(self._expectation)
        return "RecursiveMatcher"


class IsSupersetOf(RecursiveMatcher):
    def _check_additional_mapping_entries(self, candidate, expectation):
        return True, "", ""

    def _match_sequence(self, superset, subset):
        message = ""
        path = ""
        superset_index = 0
        for subset_index in range(len(subset)):
            last_superset_match_index = superset_index
            while superset_index < len(superset):
                result, message, path = self._recursive_match(
                    superset[superset_index], subset[subset_index]
                )
                if result:
                    break
                superset_index += 1
            if superset_index == len(superset):
                return (
                    False,
                    f"cannot find element due to {message}, checked elements {superset[last_superset_match_index:superset_index]}",
                    f"[{subset_index}]{path}",
                )
            superset_index += 1
        return True, "", ""


class StartsWith(UnaryMatcher):
    def __call__(self, candidate):
        if not candidate.startswith(self._expectation):
            self.last_message = f"{candidate} does not start with {self._expectation}"
            return False
        return True

    def __repr__(self):
        return f" startswith {self._expectation}"


class Contains(UnaryMatcher):
    def __call__(self, candidate):
        if self._expectation not in candidate:
            self.last_message = f"{self._expectation} not contained in {candidate}"
            return False
        return True

    def __repr__(self):
        return f" contains {self._expectation}"


class SubstringCount(CountMatcher):
    def __call__(self, candidate):
        assert getattr(candidate, "count"), "'candidate' is not a string"
        count = candidate.count(self._expectation)
        if count != self._expected_count:
            self.last_message = f"'{self._expectation}' contained {count} times, expected {self._expected_count} times"
            return False
        return True

    def __repr__(self):
        return f" contains {self._expectation} {self._expected_count} times"


class HasType(UnaryMatcher):
    def __call__(self, candidate):
        if not isinstance(candidate, self._expectation):
            self.last_message = (
                f"{candidate} has type {type(candidate)}, expected {self._expectation}"
            )
            return False
        return True

    def __repr__(self):
        return f" has type {self._expectation}"


class OneOf(UnaryMatcher):
    def __call__(self, candidate):
        if self._expectation.count(candidate) == 1:
            return True
        self.last_message = f"{candidate} not one of {self._expectation}"
        return False

    def __repr__(self):
        return f" one of {self._expectation}"
