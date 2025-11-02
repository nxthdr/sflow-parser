# Proposed sFlow Specification Errata

This document lists errors and issues found in the official sFlow specifications that are **not** part of the [documented errata](https://sflow.org/developers/errata.php). These issues were discovered during implementation and validation of the sflow-parser library and are proposed as additions to the official errata.

Each issue includes the current (incorrect) specification text and a proposed correction.

## 1. Missing Semicolons - RFC 4506 Violation

**Affected Specifications:**
- [sFlow Version 5](https://sflow.org/sflow_version_5.txt) (2004)
- [sFlow 802.11 Structures](https://sflow.org/sflow_80211.txt) (2007)
- [sFlow InfiniBand Structures](https://sflow.org/draft_sflow_infiniband_2.txt) (2013)

**Affected Structures:** ProcessorCounters (0,1001), Extended80211Rx (0,1014), ExtendedInfiniBandGrh (0,1032)

### Issue

According to [RFC 4506](https://www.rfc-editor.org/rfc/rfc4506) (XDR: External Data Representation Standard), section 4.14, **all component declarations in a struct must end with a semicolon**, including the last field. Three structures in the sFlow specifications violate this requirement by omitting semicolons on their last field(s).

**RFC 4506 Section 4.14 - Structure Syntax:**
```xdr
struct {
   component-declaration-A;
   component-declaration-B;
   ...
} identifier;
```

### Affected Structures

#### ProcessorCounters (0,1001) - sflow_version_5.txt, Page 49

**Current (Incorrect):**
```xdr
/* opaque = counter_data; enterprise = 0; format = 1001 */
struct processor {
   gauge32 cpu_5s;         /* 5 second average CPU utilization */
   gauge32 cpu_1m;         /* 1 minute average CPU utilization */
   gauge32 cpu_5m;         /* 5 minute average CPU utilization */
   unsigned hyper total_memory    /* total memory (in bytes) */
   unsigned hyper free_memory     /* free memory (in bytes) */
}
```

**Proposed Correction:**
```xdr
/* opaque = counter_data; enterprise = 0; format = 1001 */
struct processor {
   gauge32 cpu_5s;         /* 5 second average CPU utilization */
   gauge32 cpu_1m;         /* 1 minute average CPU utilization */
   gauge32 cpu_5m;         /* 5 minute average CPU utilization */
   unsigned hyper total_memory;   /* total memory (in bytes) */
   unsigned hyper free_memory;    /* free memory (in bytes) */
}
```

#### Extended80211Rx (0,1014) - sflow_80211.txt

**Current (Incorrect):**
```xdr
/* opaque = flow_data; enterprise = 0; format = 1014 */
struct extended_80211_rx {
   string ssid<32>;
   mac  bssid;
   ieee80211_version version;
   unsigned int channel;
   unsigned hyper speed;
   unsigned int rsni;
   unsigned int rcpi;
   duration_us packet_duration /* missing semicolon */
}
```

**Proposed Correction:**
```xdr
/* opaque = flow_data; enterprise = 0; format = 1014 */
struct extended_80211_rx {
   string ssid<32>;
   mac  bssid;
   ieee80211_version version;
   unsigned int channel;
   unsigned hyper speed;
   unsigned int rsni;
   unsigned int rcpi;
   duration_us packet_duration; /* add semicolon */
}
```

#### ExtendedInfiniBandGrh (0,1032) - sflow_infiniband.txt

**Current (Incorrect):**
```xdr
/* opaque = ib_grh_data; enterprise = 0; format = 1032 */
struct extended_ib_grh {
   unsigned int flow_label;
   unsigned int tc;
   gid s_gid;
   gid d_gid;
   unsigned int next_header /* missing semicolon */
   unsigned int length      /* missing semicolon */
}
```

**Proposed Correction:**
```xdr
/* opaque = flow_data; enterprise = 0; format = 1032 */
struct extended_ib_grh {
   unsigned int flow_label;
   unsigned int tc;
   gid s_gid;
   gid d_gid;
   unsigned int next_header; /* add semicolon */
   unsigned int length;      /* add semicolon */
}
```

**Note:** This correction also includes the data type fix from issue #2.

**Change:** Add semicolons to all field declarations that are missing them.

**Rationale:**
- **RFC 4506 Compliance:** The XDR specification explicitly requires semicolons after all component declarations
- **Parser Compatibility:** Ensures compatibility with all XDR parsers that strictly follow RFC 4506
- **Consistency:** Matches the syntax used in all other sFlow structure definitions

## 2. Non-Standard Data Type Names

**Specification:** [sFlow InfiniBand Structures](https://sflow.org/draft_sflow_infiniband_2.txt) (2013)

**Affected Structures:** ExtendedInfiniBandLrh (0,1031), ExtendedInfiniBandGrh (0,1032), ExtendedInfiniBandBth (0,1033)

### Issue

The InfiniBand specification uses custom data type names (`ib_lrh_data`, `ib_grh_data`, `ib_bth_data`) instead of the standard `flow_data` type, which is inconsistent with all other sFlow flow record specifications.

### Current (Incorrect) Specification

```xdr
/* opaque = ib_lrh_data; enterprise = 0; format = 1031 */
struct extended_ib_lrh { ... }

/* opaque = ib_grh_data; enterprise = 0; format = 1032 */
struct extended_ib_grh { ... }

/* opaque = ib_bth_data; enterprise = 0; format = 1033 */
struct extended_ib_bth { ... }
```

### Proposed Correction

```xdr
/* opaque = flow_data; enterprise = 0; format = 1031 */
struct extended_ib_lrh { ... }

/* opaque = flow_data; enterprise = 0; format = 1032 */
struct extended_ib_grh { ... }

/* opaque = flow_data; enterprise = 0; format = 1033 */
struct extended_ib_bth { ... }
```

**Change:** Replace custom type names with standard `flow_data` type.

**Rationale:** All other flow records in sFlow use `flow_data` as the opaque type. The custom names provide no additional semantic value and create unnecessary inconsistency.

## 3. Missing 'struct' Keyword

**Specification:** [sFlow Application Structures](https://sflow.org/sflow_application.txt) (2012)

**Affected Structures:** AppInitiator (0,2204), AppTarget (0,2205)

### Issue

Some structure definitions in the application specification omit the `struct` keyword before the structure name, which is inconsistent with XDR syntax conventions.

### Current (Inconsistent) Specification

```xdr
/* opaque = flow_data; enterprise = 0; format = 2204 */
app_initiator {
   string<> application;
}

/* opaque = flow_data; enterprise = 0; format = 2205 */
app_target {
   string<> application;
}
```

### Proposed Correction

```xdr
/* opaque = flow_data; enterprise = 0; format = 2204 */
struct app_initiator {
   string<> application;
}

/* opaque = flow_data; enterprise = 0; format = 2205 */
struct app_target {
   string<> application;
}
```

**Change:** Add the `struct` keyword before structure names.

**Rationale:** All other sFlow specifications use the `struct` keyword. Omitting it creates inconsistency and may confuse parsers expecting standard XDR syntax.

## 4. Inconsistent Format Comment Separator

**Specification:** [sFlow NVML GPU Structures](https://sflow.org/sflow_nvml.txt) (2012)

**Affected Structure:** NvidiaGpu (5703,1)

### Issue

The format comment uses a comma separator instead of a semicolon between `enterprise` and `format` fields, which is inconsistent with all other sFlow specifications.

### Current (Inconsistent) Specification

```xdr
/* opaque = counter_data; enterprise = 5703, format = 1 */
struct nvidia_gpu {
   ...
}
```

### Proposed Correction

```xdr
/* opaque = counter_data; enterprise = 5703; format = 1 */
struct nvidia_gpu {
   ...
}
```

**Change:** Replace comma with semicolon between `enterprise` and `format` fields.

**Rationale:** All other sFlow specifications use semicolons as separators in format comments. Using a comma creates unnecessary inconsistency.

## 5. Page Headers and Formatting Artifacts

**Specifications:** All text-format specifications

### Issue

The text-based specification files contain page headers, footers, and line-wrapping artifacts that can interfere with automated parsing:

- `[Page N]` markers
- `FINAL` headers
- `sFlow.org` footers
- Version markers like `v1.`
- Line wrapping mid-field causing fields to appear on multiple lines

### Example

```
FINAL                           sFlow.org
         [Page 3]

FINAL              sFlow Optical Interface Structures
      August 2016

struct example {
  unsigned int field1;      /* comment that wraps to
                               next line */
  unsigned int field2;
}
```

### Recommendation

For future specifications:
1. Provide machine-readable XDR files separate from documentation
2. Use consistent line width to avoid mid-field wrapping
3. Clearly separate documentation text from XDR definitions
4. Consider using a standard XDR format validator

**Impact:** These formatting issues don't affect the semantic correctness but make automated validation and parsing more difficult.
