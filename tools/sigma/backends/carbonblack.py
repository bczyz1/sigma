# CarbonBlack backend for sigmac created by Relativity ODA LLC
# Bartlomiej Czyz (@bczyz1) & Mateusz Wydra (@sn0w0tter)

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
import sigma

from ..parser.modifiers.base import SigmaTypeModifier
from .base import SingleTextQueryBackend
from .exceptions import NotSupportedError

fieldMappings = {
    "AccountName": "username",
    "Command": "cmdline",
    "CommandLine": "cmdline",
    "Company": "company_name",
    "ComputerName": "hostname",
    "DestinationHostname": "domain",
    "DestinationIp": "ipaddr",
    "DestinationIsIpv6": "ipv6addr:*",
    "DestinationPort": "ipport",
    "EventType": "ActionType",
    "Image": "path",
    "ImageLoaded": "modload",
    "Imphash": "md5",
    "NewProcessName": "process_name",
    "OriginalFilename": "internal_name",
    "OriginalFileName": "internal_name",
    "ParentImage": "parent_name",
    "ProcessCommandLine": "cmdline",
    "Product": "product_name",
    "ScriptBlockText": "cmdline",
    "SourceImage": "parent_name",
    "TargetFilename": "filemod",
    "TargetImage": "childproc_name",
    "TargetObject": "regmod",
    "User": "username"
}


class CarbonBlackResponseBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Windows Defender ATP Hunting Queries."""

    identifier = "carbonblack"
    active = True
    config_required = False
    reEscape = re.compile('([ "()\\\\])')
    reClear = None
    andToken = " "
    orToken = " OR "
    notToken = "-"
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " "
    valueExpression = "%s"
    nullExpression = "-%s:*"
    notNullExpression = "%s:*"
    mapExpression = "%s:%s"
    forbiddenCharacters = ['<', '>']
    double_negation = '-(-'

    def __init__(self, *args, **kwargs):
        """Initialize field mappings"""
        super().__init__(*args, **kwargs)

        self.service = None
        self.product = None
        self.category = None

    def generate(self, sigma_parser):
        try:
            self.category = sigma_parser.parsedyaml['logsource'].setdefault('category', None)
            self.product = sigma_parser.parsedyaml['logsource'].setdefault('product', None)
            self.service = sigma_parser.parsedyaml['logsource'].setdefault('service', None)
        except KeyError:
            pass
        result = super().generate(sigma_parser)
        if any(character in result for character in self.forbiddenCharacters):
            raise NotSupportedError("Carbon Black search query syntax does not allow '<' and '>' characters.")
        if self.double_negation in result:
            result = result.replace(self.double_negation, '(')
        return result

    def generateMapItemNode(self, node):
        key, value = node
        is_key_that_can_contain_path = key.endswith("Image")
        if type(value) == str:
            if key == "CommandLine":
                return self.generateNode(SigmaCarbonBlackCmdLineModifier(value))
            if is_key_that_can_contain_path:
                value = self.convert_path_to_name(key, value)
            value = self.remove_trailing_whitespaces(value)
        if type(value) == list:
            return '(' + self.generateORNode([(key, v) for v in value]) + ')'
        try:
            mapping = fieldMappings[key]
            return super().generateMapItemNode((mapping, value))
        except KeyError:
            raise NotSupportedError("No mapping defined for field '%s'" % key)

    def generateTypedValueNode(self, node):
        if isinstance(node, SigmaCarbonBlackCmdLineModifier) and isinstance(node.value, str):
            command_line = self.remove_trailing_whitespaces(node.value)
            command_line = self.remove_leading_wildcard(command_line)
            return '(cmdline:' + command_line + ')'
        # super().generateTypedValueNode(node)

    @staticmethod
    def remove_trailing_whitespaces(value):
        if value.startswith("* "):
            value = "%s%s" % (value[0], value[2:])
        if value.endswith(" *"):
            value = "%s%s" % (value[0:-2], value[-1])
        return value

    @staticmethod
    def remove_leading_wildcard(value):
        if value.startswith("*"):
            value = "%s" % (value[1:])
        return value

    @staticmethod
    def convert_path_to_name(key, value):
        is_full_path_supported = "Image" == key
        is_end_of_path = value.startswith("*\\") and value.count('\\') == 1
        is_complex_path = value.count('\\') > 1
        if is_end_of_path:
            return value[2:]  # leading wildcards carry a significant performance penalty for the search
        elif is_complex_path and not is_full_path_supported:
            raise NotSupportedError("Path from '%s' field is not supported by CarbonBlack" % key)
        else:
            return value


class SigmaCarbonBlackCmdLineModifier(SigmaTypeModifier):
    """Do not invoke any regular expressions on CarbonBlack search paramter 'cmdline'.
    This was needed due to tokenization process implemented within CarbonBlack"""
