"""
OpenCTI TAXII1 connector overrides module.
Patches existing stix2elevator functions.
"""

from stix2elevator import utils, convert_stix
from stix.data_marking import MarkingStructure
from stix_edh.isa_markings_assertions import ISAMarkingsAssertion

'''
Add support for ISA markings
'''
def apply_isa_markings(stix2x_instance, stix2x_marking):
    pass

'''
Add support for ISA markings
'''
def fix_markings():
    for stix2_instance in convert_stix.get_unfinished_marked_objects():
        object_marking_refs = []
        for marking_ref in stix2_instance.get("object_marking_refs", []):
            if isinstance(marking_ref, MarkingStructure):
                stix2x_marking = convert_stix.map_1x_markings_to_2x(marking_ref)
                if isinstance(stix2x_marking, ISAMarkingsAssertion):
                    apply_isa_markings(stix2_instance, stix2x_marking)
                elif stix2x_marking["definition_type"] == "ais":
                    convert_stix.apply_ais_markings(stix2_instance, stix2x_marking)
                    object_marking_refs.append(stix2x_marking["marking_ref"])
                else:
                    object_marking_refs.append(stix2x_marking["id"])
            else:
                object_marking_refs.append(marking_ref)

        stix2_instance["object_marking_refs"] = object_marking_refs

'''
Fix to handle empty tags (e.g. <Description/>)
'''
def process_structured_text_list(text_list):
    full_text = ""
    for text_obj in text_list.sorted:
        if text_obj.value:
            full_text += text_obj.value
    return full_text

# Override existing stix2elevator functions with modified functions above
utils.apply_isa_markings = apply_isa_markings
convert_stix.apply_isa_markings = apply_isa_markings
convert_stix.fix_markings = fix_markings
convert_stix.process_structured_text_list = process_structured_text_list