"""Fetch a small official AWS Price List snapshot for the cost study."""

import json
import re

import boto3


LOCATION = "Asia Pacific (Seoul)"
QUERIES = {
    "AWSLambda": re.compile(r"request|duration|GB-second", re.I),
    "AmazonApiGateway": re.compile(r"REST|API call|request", re.I),
    "AmazonDynamoDB": re.compile(r"on-demand|read request|write request", re.I),
    "AmazonS3": re.compile(r"PUT|GET|tag", re.I),
}


def main():
    pricing = boto3.client("pricing", region_name="us-east-1")
    rows = []
    for service, wanted in QUERIES.items():
        token = None
        while True:
            kwargs = {
                "ServiceCode": service,
                "Filters": [{"Type": "TERM_MATCH", "Field": "location", "Value": LOCATION}],
                "MaxResults": 100,
            }
            if token:
                kwargs["NextToken"] = token
            page = pricing.get_products(**kwargs)
            for raw in page["PriceList"]:
                product = json.loads(raw)
                attributes = product["product"].get("attributes", {})
                for term in product.get("terms", {}).get("OnDemand", {}).values():
                    for dimension in term.get("priceDimensions", {}).values():
                        description = dimension.get("description", "")
                        searchable = " ".join([
                            description,
                            attributes.get("usagetype", ""),
                            attributes.get("operation", ""),
                        ])
                        if wanted.search(searchable):
                            rows.append({
                                "service": service,
                                "usage_type": attributes.get("usagetype"),
                                "operation": attributes.get("operation"),
                                "description": description,
                                "unit": dimension.get("unit"),
                                "usd": dimension.get("pricePerUnit", {}).get("USD"),
                            })
            token = page.get("NextToken")
            if not token:
                break
    unique = {json.dumps(row, sort_keys=True): row for row in rows}
    print(json.dumps(list(unique.values()), indent=2))


if __name__ == "__main__":
    main()
