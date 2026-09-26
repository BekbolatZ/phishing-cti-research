# Maltego Analysis

## Objective

Maltego was evaluated as an OSINT visualization and relationship-analysis tool for the investigation of the phishing domain `delivery-usps.vip`.

The objective was to identify relationships between the investigated domain and other infrastructure entities.

## Investigation

The domain `delivery-usps.vip` was added to a new Maltego graph as a Domain entity.

Available Transforms were examined to identify possible DNS, domain, and infrastructure relationships.

However, the useful Transforms required for automated domain and DNS expansion were unavailable in the current Maltego configuration.

Therefore, no automated Transform results were used in the final investigation.

## Relationship Data

Instead, previously collected VirusTotal passive DNS and certificate information was used to document the observed relationships.

The domain had historical resolutions to:

- `43.135.155.184`
- `8.209.202.142`
- `47.245.39.108`

Historical SSL certificate relationships included:

- `usps-redelivery.art`
- `*.easyerin.com`

These relationships represent historical observations from VirusTotal and should not be interpreted as proof of common ownership or control.

## Limitations

The main limitation was the availability of Maltego Transforms in the current configuration.

Several relevant Transforms were unavailable, so the investigation did not rely on automatically generated Maltego results.

This demonstrates that OSINT investigations may depend on the availability, coverage, and configuration of individual intelligence sources.

## Conclusion

Maltego was successfully used to create an investigation graph and evaluate available relationship-analysis capabilities.

Although automated Transforms were not available for the required investigation, the relationship data collected from VirusTotal was sufficient to document the historical infrastructure associated with the investigated phishing domain.
