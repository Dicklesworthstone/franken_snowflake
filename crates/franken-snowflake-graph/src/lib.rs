//! `franken-snowflake-graph` -- typed catalog lineage graph APIs.
//!
//! This crate turns `franken-snowflake-catalog` snapshots into a deterministic
//! directed graph for agent discovery and `catalog graph --mermaid` output. The
//! public API stays independent from FrankenNetworkX internals; an internal fnx
//! mirror is built for algorithm parity, while a local adjacency index remains
//! the compatibility fallback and source of deterministic rendering.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fnx_classes::digraph::DiGraph;
use franken_snowflake_catalog::model::{
    CatalogSnapshot, ColumnCatalogEntry, DatasetField, DatasetKind, DatasetManifest, FieldRole,
    Provenance,
};
use serde::{Deserialize, Serialize};

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Stable node key used by catalog graph algorithms and renderers.
pub type NodeKey = String;

/// Stable directed edge index into [`CatalogGraph::edges`].
pub type EdgeIndex = usize;

/// Typed graph node class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogNodeKind {
    /// Secret-free profile identity.
    Profile,
    /// Snowflake database.
    Database,
    /// Snowflake schema.
    Schema,
    /// Snowflake table/view/external object.
    Object,
    /// Snowflake column.
    Column,
    /// Snowflake stage.
    Stage,
    /// Snowflake file format.
    FileFormat,
    /// Dataset manifest.
    Dataset,
}

impl CatalogNodeKind {
    /// Deterministic label prefix.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Database => "database",
            Self::Schema => "schema",
            Self::Object => "object",
            Self::Column => "column",
            Self::Stage => "stage",
            Self::FileFormat => "file_format",
            Self::Dataset => "dataset",
        }
    }
}

/// Typed graph edge class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogEdgeKind {
    /// Container edge: profile -> database -> schema -> object -> column.
    Contains,
    /// Dataset manifest points at its backing object.
    DatasetObject,
    /// Dataset field points at a backing column.
    FieldColumn,
    /// Referencing column -> referenced column.
    ForeignKey,
    /// View object -> source object.
    ViewDependsOn,
    /// Derived object/dataset -> source object/dataset.
    LineageReads,
    /// Object/export plan -> stage.
    UsesStage,
    /// Stage/export plan -> file format.
    UsesFileFormat,
}

impl CatalogEdgeKind {
    /// Deterministic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Contains => "contains",
            Self::DatasetObject => "dataset_object",
            Self::FieldColumn => "field_column",
            Self::ForeignKey => "foreign_key",
            Self::ViewDependsOn => "view_depends_on",
            Self::LineageReads => "lineage_reads",
            Self::UsesStage => "uses_stage",
            Self::UsesFileFormat => "uses_file_format",
        }
    }
}

/// Secret-free graph node payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogNode {
    /// Stable key.
    pub key: NodeKey,
    /// Node class.
    pub kind: CatalogNodeKind,
    /// Short label intended for Mermaid/SVG output.
    pub label: String,
    /// Optional fully-qualified display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualified_name: Option<String>,
    /// Source artifact provenance.
    pub provenance: Provenance,
    /// Redaction markers applied before graph emission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redactions_applied: Vec<String>,
}

/// Secret-free directed edge payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEdge {
    /// Source node key.
    pub source: NodeKey,
    /// Target node key.
    pub target: NodeKey,
    /// Edge class.
    pub kind: CatalogEdgeKind,
    /// Optional role/detail appended to the edge label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Source artifact provenance.
    pub provenance: Provenance,
    /// Redaction markers applied before graph emission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redactions_applied: Vec<String>,
}

/// Deterministic neighborhood entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelatedNode {
    /// Related node key.
    pub node: NodeKey,
    /// Traversal distance from the seed.
    pub depth: usize,
    /// True when the node was found by following an incoming edge.
    pub incoming: bool,
    /// True when the node was found by following an outgoing edge.
    pub outgoing: bool,
}

/// Internal adapter proof that the fnx graph mirrors the public graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FnxAlgorithmEvidence {
    /// Node count seen by fnx.
    pub node_count: usize,
    /// Edge count seen by fnx after collapsing parallel typed edges.
    pub edge_count: usize,
    /// Ancestors returned by fnx for the requested node.
    pub ancestors: Vec<NodeKey>,
    /// Descendants returned by fnx for the requested node.
    pub descendants: Vec<NodeKey>,
}

/// Typed directed multigraph with deterministic adjacency indexes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogGraph {
    /// Nodes keyed by stable catalog identity.
    pub nodes: BTreeMap<NodeKey, CatalogNode>,
    /// Directed typed edges.
    pub edges: Vec<CatalogEdge>,
    #[serde(skip)]
    outgoing: BTreeMap<NodeKey, BTreeSet<EdgeIndex>>,
    #[serde(skip)]
    incoming: BTreeMap<NodeKey, BTreeSet<EdgeIndex>>,
    #[serde(skip)]
    edge_keys: BTreeSet<(NodeKey, CatalogEdgeKind, NodeKey, Option<String>)>,
}

impl CatalogGraph {
    /// Construct an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edges: Vec::new(),
            outgoing: BTreeMap::new(),
            incoming: BTreeMap::new(),
            edge_keys: BTreeSet::new(),
        }
    }

    /// Build a catalog graph from a no-account or live catalog snapshot.
    #[must_use]
    pub fn from_snapshot(snapshot: &CatalogSnapshot) -> Self {
        let mut graph = Self::new();
        let dataset_profiles = snapshot
            .datasets
            .iter()
            .map(|dataset| (dataset.id.clone(), dataset.profile.clone()))
            .collect::<BTreeMap<_, _>>();

        for dataset in &snapshot.datasets {
            graph.add_dataset(dataset);
        }
        for column in &snapshot.columns {
            let profile = dataset_profiles
                .get(&column.dataset_id)
                .cloned()
                .unwrap_or_else(|| snapshot.provenance.profile_fingerprint.clone());
            graph.add_column(&profile, column, &snapshot.provenance);
        }
        for dataset in &snapshot.datasets {
            graph.add_dataset_edges(dataset);
        }

        graph
    }

    /// Number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of typed edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Insert or replace a node and ensure adjacency rows exist.
    pub fn add_node(&mut self, node: CatalogNode) {
        self.outgoing.entry(node.key.clone()).or_default();
        self.incoming.entry(node.key.clone()).or_default();
        self.nodes.insert(node.key.clone(), node);
    }

    /// Insert a typed directed edge if the same `(source, kind, target, detail)`
    /// edge is not already present.
    pub fn add_edge(&mut self, edge: CatalogEdge) {
        let edge_key = (
            edge.source.clone(),
            edge.kind,
            edge.target.clone(),
            edge.detail.clone(),
        );
        if !self.edge_keys.insert(edge_key) {
            return;
        }
        let index = self.edges.len();
        self.outgoing
            .entry(edge.source.clone())
            .or_default()
            .insert(index);
        self.incoming
            .entry(edge.target.clone())
            .or_default()
            .insert(index);
        self.edges.push(edge);
    }

    /// Ancestors of `node`: every node with a path to `node`.
    #[must_use]
    pub fn ancestors(&self, node: &str) -> Vec<NodeKey> {
        self.walk(node, Direction::Incoming)
    }

    /// Descendants of `node`: every node reachable from `node`.
    #[must_use]
    pub fn descendants(&self, node: &str) -> Vec<NodeKey> {
        self.walk(node, Direction::Outgoing)
    }

    /// Whether `to` is reachable from `from`.
    #[must_use]
    pub fn reachable(&self, from: &str, to: &str) -> bool {
        from == to || self.descendants(from).iter().any(|node| node == to)
    }

    /// Bounded bidirectional neighborhood for agent discovery.
    #[must_use]
    pub fn what_relates_to(&self, node: &str, depth: usize) -> Vec<RelatedNode> {
        if !self.nodes.contains_key(node) {
            return Vec::new();
        }
        let mut related = BTreeMap::<NodeKey, RelatedNode>::new();
        let mut queue = VecDeque::from([(node.to_owned(), 0_usize)]);
        let mut seen = BTreeSet::from([node.to_owned()]);
        while let Some((current, current_depth)) = queue.pop_front() {
            if current_depth >= depth {
                continue;
            }
            for (next, incoming) in self.neighbors_both(&current) {
                let next_depth = current_depth.saturating_add(1);
                let entry = related.entry(next.clone()).or_insert(RelatedNode {
                    node: next.clone(),
                    depth: next_depth,
                    incoming,
                    outgoing: !incoming,
                });
                entry.depth = entry.depth.min(next_depth);
                entry.incoming |= incoming;
                entry.outgoing |= !incoming;
                if seen.insert(next.clone()) {
                    queue.push_back((next, next_depth));
                }
            }
        }
        related.into_values().collect()
    }

    /// Dependency cycles over the typed directed graph.
    #[must_use]
    pub fn cycles(&self) -> Vec<Vec<NodeKey>> {
        let mut fnx_cycles = fnx_algorithms::simple_cycles(&self.to_fnx_digraph());
        // Canonicalize each cycle by ROTATING it to start at its minimum node.
        // That is deterministic without destroying the traversal direction —
        // sorting the nodes within a cycle would make A->B->C->A indistinguishable
        // from any other 3-node set, so the returned path would no longer describe
        // a traversable cycle.
        for cycle in &mut fnx_cycles {
            if let Some(min_index) = (0..cycle.len()).min_by(|&a, &b| cycle[a].cmp(&cycle[b])) {
                cycle.rotate_left(min_index);
            }
        }
        fnx_cycles.sort();
        fnx_cycles
    }

    /// Deterministic Mermaid flowchart text for `catalog graph --mermaid`.
    #[must_use]
    pub fn to_mermaid(&self) -> String {
        let mut output = String::from("flowchart LR\n");
        for node in self.nodes.values() {
            output.push_str("  ");
            output.push_str(&mermaid_node_id(&node.key));
            output.push_str("[\"");
            output.push_str(&escape_mermaid_label(&node.label));
            output.push_str("\"]\n");
        }
        for edge in self.sorted_edges() {
            output.push_str("  ");
            output.push_str(&mermaid_node_id(&edge.source));
            output.push_str(" -->|");
            output.push_str(edge.kind.as_str());
            if let Some(detail) = &edge.detail {
                output.push(' ');
                output.push_str(&escape_mermaid_label(detail));
            }
            output.push_str("| ");
            output.push_str(&mermaid_node_id(&edge.target));
            output.push('\n');
        }
        output
    }

    /// Deterministic lightweight SVG rendering of the same graph model.
    #[must_use]
    pub fn to_svg(&self) -> String {
        let width = 960_u32;
        let row_height = 72_u32;
        let height = (self.nodes.len().max(1) as u32)
            .saturating_mul(row_height)
            .saturating_add(80);
        let positions = self
            .nodes
            .keys()
            .enumerate()
            .map(|(index, key)| {
                (
                    key.clone(),
                    (
                        80_u32.saturating_add(((index % 3) as u32).saturating_mul(300)),
                        60_u32.saturating_add((index as u32).saturating_mul(row_height)),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let mut svg = format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" role=\"img\" viewBox=\"0 0 {width} {height}\">\n"
        );
        svg.push_str("  <title>Catalog lineage graph</title>\n");
        svg.push_str("  <defs><marker id=\"arrow\" markerWidth=\"10\" markerHeight=\"10\" refX=\"8\" refY=\"3\" orient=\"auto\"><path d=\"M0,0 L0,6 L9,3 z\" fill=\"#475569\"/></marker></defs>\n");
        svg.push_str("  <rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\n");
        for edge in self.sorted_edges() {
            let Some((source_x, source_y)) = positions.get(&edge.source) else {
                continue;
            };
            let Some((target_x, target_y)) = positions.get(&edge.target) else {
                continue;
            };
            svg.push_str(&format!(
                "  <line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#475569\" stroke-width=\"1.5\" marker-end=\"url(#arrow)\"><title>{}</title></line>\n",
                source_x.saturating_add(210),
                source_y.saturating_add(18),
                target_x.saturating_add(8),
                target_y.saturating_add(18),
                escape_xml(edge.kind.as_str())
            ));
        }
        for node in self.nodes.values() {
            let Some((x, y)) = positions.get(&node.key) else {
                continue;
            };
            svg.push_str(&format!(
                "  <g><rect x=\"{x}\" y=\"{y}\" width=\"220\" height=\"40\" rx=\"6\" fill=\"{}\" stroke=\"#334155\"/><text x=\"{}\" y=\"{}\" font-family=\"Inter,Arial,sans-serif\" font-size=\"13\" fill=\"#0f172a\">{}</text></g>\n",
                node_fill(node.kind),
                x.saturating_add(12),
                y.saturating_add(25),
                escape_xml(&truncate_label(&node.label, 30))
            ));
        }
        svg.push_str("</svg>\n");
        svg
    }

    /// Build an fnx mirror and return parity evidence for a node.
    #[must_use]
    pub fn fnx_evidence_for(&self, node: &str) -> FnxAlgorithmEvidence {
        let graph = self.to_fnx_digraph();
        let mut ancestors = fnx_algorithms::ancestors(&graph, node)
            .into_iter()
            .collect::<Vec<_>>();
        let mut descendants = fnx_algorithms::descendants(&graph, node)
            .into_iter()
            .collect::<Vec<_>>();
        ancestors.sort();
        descendants.sort();
        FnxAlgorithmEvidence {
            node_count: graph.node_count(),
            edge_count: graph.edge_count(),
            ancestors,
            descendants,
        }
    }

    fn add_dataset(&mut self, dataset: &DatasetManifest) {
        let provenance = dataset.provenance.clone();
        let profile_key = profile_key(&dataset.profile);
        let database_key = database_key(&dataset.profile, &dataset.database);
        let schema_key = schema_key(&dataset.profile, &dataset.database, &dataset.schema);
        let object_key = object_key(
            &dataset.profile,
            &dataset.database,
            &dataset.schema,
            &dataset.object,
        );
        let dataset_key = dataset_key(&dataset.id);

        self.add_node(node(
            profile_key.clone(),
            CatalogNodeKind::Profile,
            format!("profile:{}", dataset.profile),
            None,
            &provenance,
        ));
        self.add_node(node(
            database_key.clone(),
            CatalogNodeKind::Database,
            format!("database:{}", dataset.database),
            Some(dataset.database.clone()),
            &provenance,
        ));
        self.add_node(node(
            schema_key.clone(),
            CatalogNodeKind::Schema,
            format!("schema:{}.{}", dataset.database, dataset.schema),
            Some(format!("{}.{}", dataset.database, dataset.schema)),
            &provenance,
        ));
        self.add_node(node(
            object_key.clone(),
            CatalogNodeKind::Object,
            format!(
                "{}:{}.{}.{}",
                dataset_kind_label(dataset.kind),
                dataset.database,
                dataset.schema,
                dataset.object
            ),
            Some(format!(
                "{}.{}.{}",
                dataset.database, dataset.schema, dataset.object
            )),
            &provenance,
        ));
        self.add_node(node(
            dataset_key.clone(),
            CatalogNodeKind::Dataset,
            format!("dataset:{}", dataset.id),
            Some(dataset.id.clone()),
            &provenance,
        ));

        self.add_edge(edge(
            &profile_key,
            CatalogEdgeKind::Contains,
            &database_key,
            None,
            &provenance,
        ));
        self.add_edge(edge(
            &database_key,
            CatalogEdgeKind::Contains,
            &schema_key,
            None,
            &provenance,
        ));
        self.add_edge(edge(
            &schema_key,
            CatalogEdgeKind::Contains,
            &object_key,
            None,
            &provenance,
        ));
        self.add_edge(edge(
            &dataset_key,
            CatalogEdgeKind::DatasetObject,
            &object_key,
            None,
            &provenance,
        ));
    }

    fn add_column(
        &mut self,
        profile: &str,
        column: &ColumnCatalogEntry,
        snapshot_provenance: &Provenance,
    ) {
        let provenance = column
            .provenance
            .as_ref()
            .unwrap_or(snapshot_provenance)
            .clone();
        let object_key = object_key(profile, &column.database, &column.schema, &column.object);
        let column_key = column_key(
            profile,
            &column.database,
            &column.schema,
            &column.object,
            &column.column,
        );
        self.add_node(node(
            column_key.clone(),
            CatalogNodeKind::Column,
            format!("column:{}", column.column),
            Some(format!(
                "{}.{}.{}.{}",
                column.database, column.schema, column.object, column.column
            )),
            &provenance,
        ));
        self.add_edge(edge(
            &object_key,
            CatalogEdgeKind::Contains,
            &column_key,
            None,
            &provenance,
        ));
    }

    fn add_dataset_edges(&mut self, dataset: &DatasetManifest) {
        let dataset_key = dataset_key(&dataset.id);
        let object_key = object_key(
            &dataset.profile,
            &dataset.database,
            &dataset.schema,
            &dataset.object,
        );
        for field in &dataset.fields {
            let column_key = column_key(
                &dataset.profile,
                &dataset.database,
                &dataset.schema,
                &dataset.object,
                &field.column,
            );
            if !self.nodes.contains_key(&column_key) {
                self.add_dataset_field_column_node(dataset, field, &column_key);
                self.add_edge(edge(
                    &object_key,
                    CatalogEdgeKind::Contains,
                    &column_key,
                    None,
                    &dataset.provenance,
                ));
            }
            self.add_edge(edge(
                &dataset_key,
                CatalogEdgeKind::FieldColumn,
                &column_key,
                Some(field_role_label(field.role).to_owned()),
                &dataset.provenance,
            ));
        }
    }

    fn add_dataset_field_column_node(
        &mut self,
        dataset: &DatasetManifest,
        field: &DatasetField,
        column_key: &str,
    ) {
        self.add_node(node(
            column_key.to_owned(),
            CatalogNodeKind::Column,
            format!("column:{}", field.column),
            Some(format!(
                "{}.{}.{}.{}",
                dataset.database, dataset.schema, dataset.object, field.column
            )),
            &dataset.provenance,
        ));
    }

    fn sorted_edges(&self) -> Vec<&CatalogEdge> {
        let mut edges = self.edges.iter().collect::<Vec<_>>();
        edges.sort_by_key(|edge| {
            (
                edge.source.clone(),
                edge.kind,
                edge.target.clone(),
                edge.detail.clone(),
            )
        });
        edges
    }

    fn walk(&self, node: &str, direction: Direction) -> Vec<NodeKey> {
        if !self.nodes.contains_key(node) {
            return Vec::new();
        }
        let mut queue = VecDeque::from([node.to_owned()]);
        let mut seen = BTreeSet::<NodeKey>::from([node.to_owned()]);
        let mut result = BTreeSet::<NodeKey>::new();
        while let Some(current) = queue.pop_front() {
            for next in self.neighbors(&current, direction) {
                if seen.insert(next.clone()) {
                    result.insert(next.clone());
                    queue.push_back(next);
                }
            }
        }
        result.into_iter().collect()
    }

    fn neighbors(&self, node: &str, direction: Direction) -> Vec<NodeKey> {
        let indexes = match direction {
            Direction::Outgoing => self.outgoing.get(node),
            Direction::Incoming => self.incoming.get(node),
        };
        indexes
            .into_iter()
            .flat_map(|set| set.iter())
            .filter_map(|index| self.edges.get(*index))
            .map(|edge| match direction {
                Direction::Outgoing => edge.target.clone(),
                Direction::Incoming => edge.source.clone(),
            })
            .collect()
    }

    fn neighbors_both(&self, node: &str) -> Vec<(NodeKey, bool)> {
        let mut related = Vec::new();
        related.extend(
            self.neighbors(node, Direction::Incoming)
                .into_iter()
                .map(|neighbor| (neighbor, true)),
        );
        related.extend(
            self.neighbors(node, Direction::Outgoing)
                .into_iter()
                .map(|neighbor| (neighbor, false)),
        );
        related.sort();
        related
    }

    fn to_fnx_digraph(&self) -> DiGraph {
        let mut graph = DiGraph::strict();
        for key in self.nodes.keys() {
            graph.add_node(key.clone());
        }
        for edge in self.sorted_edges() {
            let _ = graph.add_edge(edge.source.clone(), edge.target.clone());
        }
        graph
    }
}

impl Default for CatalogGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Incoming,
    Outgoing,
}

/// Build a typed graph from a catalog snapshot.
#[must_use]
pub fn graph_from_snapshot(snapshot: &CatalogSnapshot) -> CatalogGraph {
    CatalogGraph::from_snapshot(snapshot)
}

/// Stable profile node key.
#[must_use]
pub fn profile_key(profile: &str) -> NodeKey {
    format!("profile:{profile}")
}

/// Stable database node key.
#[must_use]
pub fn database_key(profile: &str, database: &str) -> NodeKey {
    format!("{}/db:{database}", profile_key(profile))
}

/// Stable schema node key.
#[must_use]
pub fn schema_key(profile: &str, database: &str, schema: &str) -> NodeKey {
    format!("{}/schema:{schema}", database_key(profile, database))
}

/// Stable object node key.
#[must_use]
pub fn object_key(profile: &str, database: &str, schema: &str, object: &str) -> NodeKey {
    format!("{}/object:{object}", schema_key(profile, database, schema))
}

/// Stable column node key.
#[must_use]
pub fn column_key(
    profile: &str,
    database: &str,
    schema: &str,
    object: &str,
    column: &str,
) -> NodeKey {
    format!(
        "{}/column:{column}",
        object_key(profile, database, schema, object)
    )
}

/// Stable dataset node key.
#[must_use]
pub fn dataset_key(dataset_id: &str) -> NodeKey {
    format!("dataset:{dataset_id}")
}

fn node(
    key: NodeKey,
    kind: CatalogNodeKind,
    label: String,
    qualified_name: Option<String>,
    provenance: &Provenance,
) -> CatalogNode {
    CatalogNode {
        key,
        kind,
        label,
        qualified_name,
        provenance: provenance.clone(),
        redactions_applied: provenance.redactions_applied.clone(),
    }
}

fn edge(
    source: &str,
    kind: CatalogEdgeKind,
    target: &str,
    detail: Option<String>,
    provenance: &Provenance,
) -> CatalogEdge {
    CatalogEdge {
        source: source.to_owned(),
        target: target.to_owned(),
        kind,
        detail,
        provenance: provenance.clone(),
        redactions_applied: provenance.redactions_applied.clone(),
    }
}

fn dataset_kind_label(kind: DatasetKind) -> &'static str {
    match kind {
        DatasetKind::Table => "table",
        DatasetKind::View => "view",
        DatasetKind::MaterializedView => "materialized_view",
        DatasetKind::ExternalTable => "external_table",
    }
}

fn field_role_label(role: FieldRole) -> &'static str {
    match role {
        FieldRole::EntityKey => "entity_key",
        FieldRole::TimeIndex => "time_index",
        FieldRole::KnownAt => "known_at",
        FieldRole::Feature => "feature",
        FieldRole::Label => "label",
        FieldRole::Metadata => "metadata",
    }
}

fn mermaid_node_id(key: &str) -> String {
    let mut id = String::from("n_");
    for character in key.chars() {
        if character.is_ascii_alphanumeric() {
            id.push(character.to_ascii_lowercase());
        } else {
            id.push('_');
        }
    }
    id.push('_');
    id.push_str(&stable_hex(key));
    id
}

fn stable_hex(value: &str) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Escape a label for Mermaid `["..."]` node text and `-->|...|` edge labels.
///
/// Mermaid does **not** honor C-style backslash escapes inside quoted labels;
/// the supported way to carry reserved characters is the HTML entity form,
/// because Mermaid renders the label as HTML. A raw `"` closes the `["..."]`
/// quoting early, and a raw `[`/`]`/`{`/`}`/`(`/`)`/`|` can break the node or
/// inject additional flowchart syntax — and catalog-derived names (legally
/// quoted Snowflake identifiers) can contain any of these. Encode them all as
/// HTML entities, neutralize `&`/`<`/`>` against HTML injection in the rendered
/// SVG, and collapse every line separator (`\n`, `\r`, U+2028, U+2029) to a
/// space so a label always stays on one line.
fn escape_mermaid_label(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '"' => escaped.push_str("&quot;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '[' => escaped.push_str("&#91;"),
            ']' => escaped.push_str("&#93;"),
            '{' => escaped.push_str("&#123;"),
            '}' => escaped.push_str("&#125;"),
            '(' => escaped.push_str("&#40;"),
            ')' => escaped.push_str("&#41;"),
            '|' => escaped.push_str("&#124;"),
            '\n' | '\r' | '\u{2028}' | '\u{2029}' => escaped.push(' '),
            other => escaped.push(other),
        }
    }
    escaped
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn truncate_label(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    let mut output = value
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>();
    output.push_str("...");
    output
}

fn node_fill(kind: CatalogNodeKind) -> &'static str {
    match kind {
        CatalogNodeKind::Profile => "#e0f2fe",
        CatalogNodeKind::Database => "#dcfce7",
        CatalogNodeKind::Schema => "#fef9c3",
        CatalogNodeKind::Object => "#fae8ff",
        CatalogNodeKind::Column => "#f1f5f9",
        CatalogNodeKind::Stage => "#ffedd5",
        CatalogNodeKind::FileFormat => "#ede9fe",
        CatalogNodeKind::Dataset => "#fee2e2",
    }
}

/// Convenient re-exports for callers and tests.
pub mod prelude {
    pub use crate::{
        CatalogEdge, CatalogEdgeKind, CatalogGraph, CatalogNode, CatalogNodeKind,
        FnxAlgorithmEvidence, RelatedNode, VERSION, column_key, database_key, dataset_key,
        graph_from_snapshot, object_key, profile_key, schema_key,
    };
}

#[cfg(test)]
mod tests {
    use franken_snowflake_catalog::model::{
        DataSourceClass, DatasetField, DtypeClass, ProvenanceSource, RightsClass, RoleConfidence,
        SCHEMA_VERSION,
    };

    use super::*;

    fn provenance() -> Provenance {
        Provenance {
            source: ProvenanceSource::Fixture,
            data_source: DataSourceClass::Fixture,
            snapshot_id: "catalog-snapshot-fixture-events-v1".to_owned(),
            discovered_at: "2026-06-25T00:00:00Z".to_owned(),
            profile_fingerprint: "profile-fp-demo".to_owned(),
            object_fingerprint: "snowflake-scope:ANALYTICS.PUBLIC.EVENTS_DAILY".to_owned(),
            command_id: "catalog.scan".to_owned(),
            trace_id: "trace-fixture".to_owned(),
            redactions_applied: vec!["profile_host".to_owned()],
        }
    }

    fn fixture_snapshot() -> CatalogSnapshot {
        let provenance = provenance();
        let dataset = DatasetManifest {
            id: "events_daily".to_owned(),
            profile: "demo".to_owned(),
            database: "ANALYTICS".to_owned(),
            schema: "PUBLIC".to_owned(),
            object: "EVENTS_DAILY".to_owned(),
            kind: DatasetKind::Table,
            rights_class: RightsClass::Restricted,
            default_limit: 1_000,
            max_rows_without_export: 50_000,
            description: None,
            provenance: provenance.clone(),
            fields: vec![
                DatasetField {
                    column: "EVENT_DATE".to_owned(),
                    role: FieldRole::TimeIndex,
                    dtype: DtypeClass::Date,
                    required: true,
                    role_confidence: RoleConfidence::Confirmed,
                },
                DatasetField {
                    column: "ENTITY_ID".to_owned(),
                    role: FieldRole::EntityKey,
                    dtype: DtypeClass::String,
                    required: true,
                    role_confidence: RoleConfidence::Confirmed,
                },
                DatasetField {
                    column: "VALUE".to_owned(),
                    role: FieldRole::Feature,
                    dtype: DtypeClass::Number,
                    required: false,
                    role_confidence: RoleConfidence::Inferred,
                },
            ],
        };
        let columns = dataset
            .fields
            .iter()
            .enumerate()
            .map(|(index, field)| ColumnCatalogEntry {
                dataset_id: dataset.id.clone(),
                database: dataset.database.clone(),
                schema: dataset.schema.clone(),
                object: dataset.object.clone(),
                column: field.column.clone(),
                ordinal: (index + 1) as u32,
                snowflake_type: field.dtype.default_binding_type().to_owned(),
                dtype_class: field.dtype,
                nullable: !field.required,
                precision: None,
                scale: None,
                length: None,
                aliases: Vec::new(),
                comment: None,
                tags: Vec::new(),
                provenance: Some(provenance.clone()),
            })
            .collect::<Vec<_>>();
        CatalogSnapshot {
            schema_version: SCHEMA_VERSION.to_owned(),
            provenance,
            datasets: vec![dataset],
            columns,
            operators: Vec::new(),
        }
    }

    #[test]
    fn builds_catalog_graph_from_snapshot() {
        let graph = CatalogGraph::from_snapshot(&fixture_snapshot());
        assert_eq!(graph.node_count(), 8);
        assert_eq!(graph.edge_count(), 10);
        assert!(graph.reachable(
            &dataset_key("events_daily"),
            &object_key("demo", "ANALYTICS", "PUBLIC", "EVENTS_DAILY")
        ));
        assert!(graph.reachable(
            &profile_key("demo"),
            &column_key("demo", "ANALYTICS", "PUBLIC", "EVENTS_DAILY", "VALUE")
        ));
        assert_eq!(
            graph.ancestors(&column_key(
                "demo",
                "ANALYTICS",
                "PUBLIC",
                "EVENTS_DAILY",
                "VALUE"
            )),
            vec![
                database_key("demo", "ANALYTICS"),
                dataset_key("events_daily"),
                object_key("demo", "ANALYTICS", "PUBLIC", "EVENTS_DAILY"),
                profile_key("demo"),
                schema_key("demo", "ANALYTICS", "PUBLIC"),
            ]
        );
        assert_eq!(graph.cycles(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn bounded_neighborhood_marks_incoming_and_outgoing() {
        let graph = CatalogGraph::from_snapshot(&fixture_snapshot());
        let object = object_key("demo", "ANALYTICS", "PUBLIC", "EVENTS_DAILY");
        let related = graph.what_relates_to(&object, 1);
        assert!(
            related
                .iter()
                .any(|node| node.node == dataset_key("events_daily") && node.incoming)
        );
        assert!(related.iter().any(|node| node.node
            == column_key("demo", "ANALYTICS", "PUBLIC", "EVENTS_DAILY", "VALUE")
            && node.outgoing));
    }

    #[test]
    fn detects_lineage_cycles() {
        let mut graph = CatalogGraph::from_snapshot(&fixture_snapshot());
        let first = object_key("demo", "ANALYTICS", "PUBLIC", "EVENTS_DAILY");
        let second = "dataset:derived_events".to_owned();
        graph.add_node(node(
            second.clone(),
            CatalogNodeKind::Dataset,
            "dataset:derived_events".to_owned(),
            Some("derived_events".to_owned()),
            &provenance(),
        ));
        graph.add_edge(edge(
            &first,
            CatalogEdgeKind::LineageReads,
            &second,
            None,
            &provenance(),
        ));
        graph.add_edge(edge(
            &second,
            CatalogEdgeKind::LineageReads,
            &first,
            None,
            &provenance(),
        ));
        assert_eq!(graph.cycles(), vec![vec![second, first]]);
    }

    #[test]
    fn renders_deterministic_mermaid_and_svg() {
        let graph = CatalogGraph::from_snapshot(&fixture_snapshot());
        let mermaid = graph.to_mermaid();
        assert!(mermaid.starts_with("flowchart LR\n"));
        assert!(mermaid.contains("[\"dataset:events_daily\"]"));
        assert!(mermaid.contains("-->|field_column time_index|"));
        assert!(!mermaid.contains("snowflakecomputing.com"));

        let svg = graph.to_svg();
        assert!(svg.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""));
        assert!(svg.contains("Catalog lineage graph"));
        assert!(svg.contains("dataset:events_daily"));
    }

    #[test]
    fn mermaid_label_escaping_neutralizes_structural_chars() {
        // A quoted Snowflake identifier can legally contain Mermaid-structural
        // characters; backslash escaping does not neutralize them in Mermaid
        // (it ignores C-style escapes inside ["..."]). They must be HTML-entity
        // encoded so they cannot close the node text or inject extra syntax.
        let escaped = escape_mermaid_label("EV\"]click[\"x");
        for raw in ['"', '[', ']', '{', '}', '(', ')', '|'] {
            assert!(
                !escaped.contains(raw),
                "raw {raw:?} must not survive escaping: {escaped}"
            );
        }
        assert!(escaped.contains("&quot;"));
        assert!(escaped.contains("&#91;")); // [
        assert!(escaped.contains("&#93;")); // ]
        // No backslash escaping is emitted (Mermaid does not honor it).
        assert!(!escaped.contains('\\'));
        // Every line separator collapses to a single space.
        assert_eq!(
            escape_mermaid_label("a\nb\rc\u{2028}d\u{2029}e"),
            "a b c d e"
        );
    }

    #[test]
    fn mermaid_injection_in_object_name_cannot_add_nodes() {
        // A catalog object name crafted to break the bracket and inject a node
        // must render as exactly one node, with no stray ["..."] openings.
        let mut snapshot = fixture_snapshot();
        if let Some(dataset) = snapshot.datasets.first_mut() {
            dataset.object = "EV\"]evil[\"x".to_owned();
        }
        for column in &mut snapshot.columns {
            column.object = "EV\"]evil[\"x".to_owned();
        }
        let graph = CatalogGraph::from_snapshot(&snapshot);
        let mermaid = graph.to_mermaid();
        // One ["..."] opening per node; injection would create extra ones.
        assert_eq!(mermaid.matches("[\"").count(), graph.node_count());
        assert!(!mermaid.contains("evil[\""));
    }

    #[test]
    fn cycles_preserve_loop_order_not_alphabetical_order() {
        // Regression for the per-cycle sort that discarded traversal order: a
        // 3-cycle a->c->b->a must come back rotated to its min node in LOOP
        // order ([a, c, b]), not alphabetized ([a, b, c]).
        let mut graph = CatalogGraph::from_snapshot(&fixture_snapshot());
        let nodes = ["cyc_a", "cyc_c", "cyc_b"];
        for key in nodes {
            graph.add_node(node(
                key.to_owned(),
                CatalogNodeKind::Dataset,
                key.to_owned(),
                None,
                &provenance(),
            ));
        }
        // Loop edges: cyc_a -> cyc_c -> cyc_b -> cyc_a.
        for (from, to) in [("cyc_a", "cyc_c"), ("cyc_c", "cyc_b"), ("cyc_b", "cyc_a")] {
            graph.add_edge(edge(
                from,
                CatalogEdgeKind::LineageReads,
                to,
                None,
                &provenance(),
            ));
        }
        let injected = graph
            .cycles()
            .into_iter()
            .find(|cycle| cycle.iter().any(|node| node == "cyc_a"))
            .unwrap_or_default();
        assert_eq!(
            injected,
            vec!["cyc_a".to_owned(), "cyc_c".to_owned(), "cyc_b".to_owned()],
            "cycle must keep loop order rotated to its min node, not be alphabetized"
        );
    }

    #[test]
    fn fnx_evidence_matches_local_queries() {
        let graph = CatalogGraph::from_snapshot(&fixture_snapshot());
        let object = object_key("demo", "ANALYTICS", "PUBLIC", "EVENTS_DAILY");
        let evidence = graph.fnx_evidence_for(&object);
        assert_eq!(evidence.node_count, graph.node_count());
        assert_eq!(evidence.ancestors, graph.ancestors(&object));
        assert_eq!(evidence.descendants, graph.descendants(&object));
    }
}
