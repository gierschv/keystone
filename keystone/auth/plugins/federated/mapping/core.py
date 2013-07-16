'''
Created on 5 Jun 2013

@author: kwss
'''
from xml.etree import ElementTree

from keystone.common import config



CONF = config.CONF

class Default(object):
    def __init__(self):
        mapping_file = CONF.auth.get("mapping_file")
        self.mapping_tree = ElementTree.parse(mapping_file) 

    def map(self, attributes):
        valid_mappings = []
        # Call the mapping back end
        for mapping in self.mapping_tree.getroot().findall("AttributeMapping"):
            match = True
            
            external = mapping.find("ExternalAttributes")
            for attribute in external.findall("Attribute"):
                attribute_type = attribute.get("type")
                requirement = attribute.get("requirement")
                if requirement == "any":
                    if attribute_type in attributes.keys():
                        pass
                    else:
                        match = False
                else:
                    # Get the values for this attribute
                    values = []
                    for value in attribute.findall("AttributeValue"):
                        values.append(value.text)
                    if requirement == "one":
                        if attribute_type in attributes.keys():
                            # Check if one of the values is present
                            found = False;
                            user_values = attributes.get(attribute_type)
                            for val in values:
                                if val in user_values:                                   
                                    found = True                               
                            if not found:                                
                                match = False                           
                    if requirement == "all":
                        if attribute_type in attributes.keys():
                            # Check if one of the values is present
                            found = True;
                            user_values = attributes.get(attribute_type)
                            for val in values:
                                if not val in user_values:                                   
                                    found = False     
                            if not found:                               
                                match = False
                    if requirement == "not":
                        if attribute_type in attributes.keys():
                            # Check if one of the values is present
                            found = False;
                            user_values = attributes.get(attribute_type)
                            for val in values:
                                if val in user_values:                                   
                                    found = True     
                            if found:                               
                                match = False
                                
                        else:
                            match = True;
            if match:
               
                valid_mappings.append(self.tree_to_dict(mapping))
        return valid_mappings
            
    def tree_to_dict(self, mapping):
        attribute_dict = {}
        attributes = mapping.find("InternalAttributes").findall("Attribute")        
        for attribute in attributes:
            attribute_type = attribute.get("type")
            values = [val.text for val in attribute.findall("AttributeValue")]           
            if attribute_dict.get(attribute_type):
                for value in values:
                    attribute_dict[attribute_type].append(value)
            else:
                attribute_dict[attribute_type] = values       
        return attribute_dict
                