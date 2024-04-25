from sdjwt.adapter import DataAttributesAdapter, DataAttribute


def convert_data_attributes_to_json_schema(data_attributes: list) -> dict:
    to_be_converted_data_attributes = [
        DataAttribute(
            name=item["name"],
            description=item["description"],
            limited_disclosure=item["limitedDisclosure"],
            data_type=item["dataType"],
            value=None,  # Set value to None
        )
        for item in data_attributes
    ]
    data_attributes_json_schema = DataAttributesAdapter(
        data_attributes=to_be_converted_data_attributes
    ).to_json_schema()
    return data_attributes_json_schema


def convert_data_attributes_to_credential(data_attributes: list) -> dict:
    to_be_converted_data_attributes = [
        DataAttribute(
            name=item["name"],
            value=item["value"],
        )
        for item in data_attributes
    ]
    data_attributes_json_schema = DataAttributesAdapter(
        data_attributes=to_be_converted_data_attributes
    ).to_credential()
    return data_attributes_json_schema


def validate_data_attribute_schema_against_data_attribute_values(
    data_attribute_schema: list, data_attribute_values: list
):
    error_messages = []
    data_attribute_names = {item["name"]: item for item in data_attribute_schema}

    for item in data_attribute_values:
        name = item["name"]

        if name not in data_attribute_names:
            error_messages.append(f"Error: Name '{name}' not found in schema.")
        else:
            pass

    if error_messages:
        error_message = "\n".join(error_messages)
        raise ValueError(error_message)
    else:
        return True
