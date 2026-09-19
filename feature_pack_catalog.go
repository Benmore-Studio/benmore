package main

// Curated feature-pack catalog and manifest assembly.

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func featureCatalog() []FeatureCatalogEntry {
	return []FeatureCatalogEntry{
		{Slug: "kanban", Name: "Kanban", Version: "1.0.0", Description: "Boards, columns, cards, status history, and a drag/drop page shell."},
		{Slug: "notify-hub", Name: "Notify Hub", Version: "1.0.0", Description: "Notifications inbox, preferences, broadcast flow, and unread counts."},
		{Slug: "foundry", Name: "Foundry Clone", Version: "1.0.0", Description: "Project intake, artifact review, evaluation status, and a foundry-style workspace page."},
		{Slug: "approvals", Name: "Approvals Queue", Version: "1.0.0", Description: "Request/approve/reject workflow starter."},
		{Slug: "crm-pipeline", Name: "CRM Pipeline", Version: "1.0.0", Description: "Leads, stages, activities, and pipeline board starter."},
		{Slug: "audit-feed", Name: "Audit Activity Feed", Version: "1.0.0", Description: "Append-only activity rows and a timeline page."},
	}
}

func featureCatalogSlugs() map[string]FeatureCatalogEntry {
	out := map[string]FeatureCatalogEntry{}
	for _, e := range featureCatalog() {
		out[e.Slug] = e
	}
	return out
}

func BuildCuratedFeaturePack(slug string) (FeaturePack, map[string][]byte, error) {
	entry, ok := featureCatalogSlugs()[slug]
	if !ok {
		return FeaturePack{}, nil, fmt.Errorf("unknown curated feature pack %q", slug)
	}
	pack := FeaturePack{
		APIVersion: featurePackAPIVersion,
		Kind:       "FeaturePack",
		Name:       entry.Name,
		Slug:       entry.Slug,
		Version:    entry.Version,
		Source:     FeaturePackSource{App: "curated", Env: "catalog"},
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	files := map[string][]byte{}
	switch slug {
	case "kanban":
		pack.SchemaModels = []FeaturePackModel{
			curatedModel("Board", `model Board {
  id Int @id @default(autoincrement())
  name String
  created_at DateTime @default(now())
}`),
			curatedModel("BoardColumn", `model BoardColumn {
  id Int @id @default(autoincrement())
  board_id Int
  name String
  position Int @default(0)
  created_at DateTime @default(now())
}`),
			curatedModel("BoardCard", `model BoardCard {
  id Int @id @default(autoincrement())
  board_id Int
  column_id Int
  title String
  description String?
  assignee_id Int?
  priority String @default("normal")
  due_at DateTime?
  position Int @default(0)
  status String @default("open")
  created_at DateTime @default(now())
}`),
			curatedModel("BoardCardStatusHistory", `model BoardCardStatusHistory {
  id Int @id @default(autoincrement())
  card_id Int
  from_column_id Int?
  to_column_id Int?
  from_status String?
  to_status String
  changed_by Int?
  note String?
  created_at DateTime @default(now())
}`),
		}
		files["static/kanban.tsx"] = []byte(curatedKanbanTSX)
		files["flows/kanban-move-card.yaml"] = []byte(curatedKanbanMoveFlowYAML)
	case "notify-hub":
		pack.SchemaModels = []FeaturePackModel{
			curatedModel("Notification", `model Notification {
  id Int @id @default(autoincrement())
  user_id Int?
  broadcast_id Int?
  title String
  body String
  channel String @default("in_app")
  topic String @default("general")
  priority String @default("normal")
  link String?
  read_at DateTime?
  created_at DateTime @default(now())
}`),
			curatedModel("NotificationPreference", `model NotificationPreference {
  id Int @id @default(autoincrement())
  user_id Int
  topic String @default("general")
  in_app_enabled Boolean @default(true)
  email_enabled Boolean @default(false)
  created_at DateTime @default(now())
}`),
			curatedModel("NotificationBroadcast", `model NotificationBroadcast {
  id Int @id @default(autoincrement())
  title String
  body String
  audience String @default("all")
  channel String @default("in_app")
  topic String @default("general")
  sent_by Int?
  sent_at DateTime?
  created_at DateTime @default(now())
}`),
		}
		files["static/notify-hub.tsx"] = []byte(curatedNotifyHubTSX)
		files["flows/notify-hub-broadcast.yaml"] = []byte(curatedNotifyHubBroadcastFlowYAML)
	case "foundry":
		pack.SchemaModels = []FeaturePackModel{
			curatedModel("FoundryProject", `model FoundryProject {
  id Int @id @default(autoincrement())
  name String
  stage String @default("intake")
  owner String?
  priority String @default("normal")
  due_at DateTime?
  created_at DateTime @default(now())
}`),
			curatedModel("FoundryArtifact", `model FoundryArtifact {
  id Int @id @default(autoincrement())
  project_id Int
  title String
  kind String @default("document")
  status String @default("draft")
  reviewer String?
  notes String?
  created_at DateTime @default(now())
}`),
			curatedModel("FoundryEvaluation", `model FoundryEvaluation {
  id Int @id @default(autoincrement())
  project_id Int
  score Int?
  verdict String @default("pending")
  notes String?
  created_at DateTime @default(now())
}`),
			curatedModel("FoundryReview", `model FoundryReview {
  id Int @id @default(autoincrement())
  project_id Int
  artifact_id Int?
  reviewer String?
  status String @default("queued")
  decision String?
  notes String?
  created_at DateTime @default(now())
}`),
		}
		files["static/foundry.tsx"] = []byte(curatedFoundryTSX)
		files["flows/foundry-advance.yaml"] = []byte(curatedFoundryAdvanceFlowYAML)
	default:
		files["static/"+slug+".tsx"] = []byte("export default function Feature(){ return <main><h1>" + entry.Name + "</h1></main>; }\n")
	}
	for p, b := range files {
		pack.Files = append(pack.Files, FeaturePackFile{Path: p, SHA256: hashBytesSHA256(b), Size: int64(len(b))})
		if strings.HasPrefix(p, "static/") {
			pack.StaticAssets = appendUnique(pack.StaticAssets, p)
			pack.Routes = appendUnique(pack.Routes, routeForStaticPath(p))
		}
		if strings.HasPrefix(p, "flows/") {
			pack.Flows = appendUnique(pack.Flows, strings.TrimSuffix(strings.TrimPrefix(p, "flows/"), filepath.Ext(p)))
		}
		pack.Routes = appendUniqueMany(pack.Routes, scanFeatureRoutes(string(b))...)
		pack.EnvRefs = appendUniqueMany(pack.EnvRefs, scanFeatureEnvRefs(string(b))...)
	}
	sort.Slice(pack.Files, func(i, j int) bool { return pack.Files[i].Path < pack.Files[j].Path })
	sort.Strings(pack.Flows)
	sort.Strings(pack.Routes)
	sort.Strings(pack.StaticAssets)
	sort.Strings(pack.EnvRefs)
	return pack, files, nil
}

func curatedModel(name, src string) FeaturePackModel {
	models, err := ParsePrismaSchema(src)
	out := FeaturePackModel{Name: name, Source: src}
	if err == nil && len(models) > 0 {
		out.Table = models[0].Table
		for _, f := range models[0].Fields {
			out.Fields = append(out.Fields, f.Name)
		}
	}
	return out
}
