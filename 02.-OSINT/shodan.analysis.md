# Shodan Analysis

## Investigated Infrastructure

The domain `delivery-usps.vip` was historically associated with three IP addresses according to VirusTotal passive DNS data:

- `43.135.155.184`
- `8.209.202.142`
- `47.245.39.108`

These IP addresses were investigated using Shodan to determine whether publicly indexed infrastructure information was available.

## Shodan Results

| IP Address | Shodan Result |
|---|---|
| 43.135.155.184 | No results found |
| 8.209.202.142 | No results found |
| 47.245.39.108 | No results found |

Shodan did not provide indexed information for any of the three investigated IP addresses at the time of analysis.

## Analysis

The absence of Shodan results does not mean that the IP addresses are safe or inactive. It only indicates that Shodan did not have publicly indexed information available for these addresses during the investigation.

This demonstrates an important limitation of OSINT sources: different platforms may contain different types of historical or current information.

VirusTotal provided historical DNS relationships for the investigated domain, while Shodan did not provide additional infrastructure information for the associated IP addresses.

## Conclusion

The Shodan investigation did not reveal additional information about the historical IP addresses associated with `delivery-usps.vip`.

The result was still useful because it demonstrated that OSINT investigations depend on multiple data sources and that the absence of data from one source should not be interpreted as evidence that an indicator is benign.
