from urllib.parse import urlparse, parse_qs


def get_url_parameter(url, parameter_name):
    parsed_url = urlparse(url)
    parsed_query = parse_qs(parsed_url.query)
    return parsed_query.get(parameter_name)
