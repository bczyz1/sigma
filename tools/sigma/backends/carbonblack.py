# Output backends for sigmac
# Copyright 2018 Thomas Patzke

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re

from .base import SingleTextQueryBackend
from .exceptions import NotSupportedError


class CarbonBlackResponseBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Windows Defender ATP Hunting Queries."""

    identifier = "carbonblack"
    active = True
    config_required = False

    # \   -> \\
    # \*  -> \*
    # \\* -> \\*
    # reEscape = re.compile('("|(?<!\\\\)\\\\(?![*?\\\\]))')
    reEscape = re.compile('(")')
    reClear = None
    andToken = " "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " "
    valueExpression = "\"%s\""
    nullExpression = "NOT %s=\"*\""
    notNullExpression = "%s=\"*\""
    mapExpression = "%s:%s"

    def __init__(self, *args, **kwargs):
        """Initialize field mappings"""
        super().__init__(*args, **kwargs)
        self.fieldMappings = {  # mapping between Sigma and ATP field names Supported values: (field name
            # mapping, value mapping): distinct mappings for field name and value, may be a string (direct mapping)
            # or function maps name/value to ATP target value (mapping function,): receives field name and value as
            # parameter, return list of 2 element tuples (destination field name and value) (replacement, ): Replaces
            # field occurrence with static string
            "AccountName": ("username", self.default_value_mapping),
            "Command": ("cmdline", self.default_value_mapping),
            "CommandLine": ("cmdline", self.default_value_mapping),
            "Company": ("company_name", self.default_value_mapping),
            "ComputerName": ("hostname", self.default_value_mapping),
            "DestinationHostname": ("domain", self.default_value_mapping),
            "DestinationIp": ("ipaddr", self.default_value_mapping),
            "DestinationIsIpv6": ("ipv6addr:*",),
            "DestinationPort": ("ipport", self.default_value_mapping),
            "EventType": ("ActionType", self.default_value_mapping),
            "Image": ("process_name", self.default_value_mapping),
            "ImageLoaded": ("modload", self.default_value_mapping),
            "Imphash": ("md5", self.default_value_mapping),
            "NewProcessName": ("process_name", self.default_value_mapping),
            "OriginalFilename": ("internal_name", self.default_value_mapping),
            "OriginalFileName": ("internal_name", self.default_value_mapping),
            "ParentImage": ("parent_name", self.default_value_mapping),
            "ProcessCommandLine": ("cmdline", self.default_value_mapping),
            "Product": ("product_name", self.default_value_mapping),
            "SourceImage": ("parent_name", self.default_value_mapping),
            "TargetFilename": ("filemod", self.default_value_mapping),
            "TargetImage": ("childproc_name", self.default_value_mapping),
            "TargetObject": ("regmod", self.default_value_mapping),
            "User": ("username", self.default_value_mapping),
        }

    def default_value_mapping(self, val):
        op = ":"
        val = self.cleanValue(val)
        return "%s\"%s\"" % (op, val)

    def generate(self, sigmaparser):
        self.table = None
        try:
            self.category = sigmaparser.parsedyaml['logsource'].setdefault('category', None)
            self.product = sigmaparser.parsedyaml['logsource'].setdefault('product', None)
            self.service = sigmaparser.parsedyaml['logsource'].setdefault('service', None)
        except KeyError:
            self.category = None
            self.product = None
            self.service = None

        # if (self.category, self.product, self.service) == ("process_creation", "windows", None):
        #     self.table = "ProcessCreationEvents"
        # elif (self.category, self.product, self.service) == (None, "windows", "powershell"):
        #     self.table = "MiscEvents"
        #     self.orToken = ", "

        return super().generate(sigmaparser)

    def generateMapItemNode(self, node):
        """
        ATP queries refer to event tables instead of Windows logging event identifiers. This method catches conditions that refer to this field
        and creates an appropriate table reference.
        """
        key, value = node
        if type(value) == list:  # handle map items with values list like multiple OR-chained conditions
            return self.generateORNode(
                [(key, v) for v in value]
            )
        elif key == "EventID":  # EventIDs are not reflected in condition but in table selection
            if self.product == "windows":
                if self.service == "sysmon" and value == 1 \
                        or self.service == "security" and value == 4688:  # Process Execution
                    self.table = "ProcessCreationEvents"
                    return None
                elif self.service == "sysmon" and value == 3:  # Network Connection
                    self.table = "NetworkCommunicationEvents"
                    return None
                elif self.service == "sysmon" and value == 7:  # Image Load
                    self.table = "ImageLoadEvents"
                    return None
                elif self.service == "sysmon" and value == 8:  # Create Remote Thread
                    self.table = "MiscEvents"
                    return "ActionType == \"CreateRemoteThreadApiCall\""
                elif self.service == "sysmon" and value == 11:  # File Creation
                    self.table = "FileCreationEvents"
                    return None
                elif self.service == "sysmon" and value == 13 \
                        or self.service == "security" and value == 4657:  # Set Registry Value
                    self.table = "RegistryEvents"
                    return "ActionType == \"RegistryValueSet\""
                elif self.service == "security" and value == 4624:
                    self.table = "LogonEvents"
                    return None
        elif type(value) in (str, int):  # default value processing
            try:
                mapping = self.fieldMappings[key]
            except KeyError:
                raise NotSupportedError("No mapping defined for field '%s'" % key)
            if len(mapping) == 1:
                mapping = mapping[0]
                if type(mapping) == str:
                    return mapping
                elif callable(mapping):
                    conds = mapping(key, value)
                    return self.generateSubexpressionNode(
                        self.generateANDNode(
                            [cond for cond in mapping(key, value)]
                        )
                    )
            elif len(mapping) == 2:
                result = list()
                for map_item, val in zip(mapping, node):
                    if type(map_item) == str:
                        result.append(map_item)
                    elif callable(map_item):
                        result.append(map_item(val))
                return "{}{}".format(*result)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))

        return super().generateMapItemNode(node)

    def generateAggregation(self, agg):
        pass
