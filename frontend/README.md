# AnveshakX Frontend — SOC Operations Center Dashboard

Modern cybersecurity Security Operations Center (SOC) dashboard built with **React 18**, **Vite**, and **Tailwind CSS**.

---

## 🚀 How to Run Frontend

### 1. Prerequisites
Ensure you have **Node.js** (v18 or higher) and **npm** installed:
```bash
node -v
npm -v
```

---

### 2. Navigate to Frontend Directory
From the root of the project:
```bash
cd frontend
```

---

### 3. Install Dependencies
```bash
npm install
```

---

### 4. Start the Development Server
```bash
npm run dev
```

The frontend will start instantly and be accessible at:
👉 **[http://localhost:5173](http://localhost:5173)**

---

### 5. Build for Production
To generate an optimized production bundle:
```bash
npm run build
```
The output will be generated in the `dist/` directory.

To preview the production build locally:
```bash
npm run preview
```

---

## 🛠️ Tech Stack & Key Libraries
- **React 18**: UI component framework
- **Vite**: Ultra-fast build tool and dev server
- **Tailwind CSS**: Dark SOC styling (`#090d16` background, neon cyan, emerald, amber, crimson accents)
- **React Flow (`reactflow`)**: Interactive attack and infrastructure relationship graph
- **Leaflet & React-Leaflet**: Interactive world map plotting MTA relay nodes and source infrastructure
- **Recharts**: Threat severity distribution charts
- **Lucide React**: Cybersecurity and interface iconography
- **Axios**: API client communicating with FastAPI backend at `http://localhost:8000/api/v1`

---

## 📱 Pages & Features

| Route | Page | Purpose |
|---|---|---|
| `/` | **SOC Dashboard** | Real-time threat metrics, severity distribution, recent cases |
| `/upload` | **Analyze Email** | Drag-and-drop `.eml` dropzone + **1-Click Demo Scenarios** (BEC, Phishing, Impersonation, Legitimate) |
| `/analysis` | **Forensic Workspace** | Multi-tab analysis: Threat score, headers, authentication, relay hops, URLs, attachments, Geo map, attack graph, IOCs, timeline, and SHA-256 evidence certificate |
| `/cases` | **Case Registry** | Searchable case database with severity filtering and case management |
| PDF Export | **PDF Report** | 1-click download of official forensic investigation report |
