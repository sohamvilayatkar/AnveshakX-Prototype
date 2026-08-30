import axios from 'axios';

const API_BASE = '/api/v1';

const apiClient = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: {
    'Accept': 'application/json'
  }
});

export const api = {
  // Health
  getHealth: async () => {
    const res = await apiClient.get('/health');
    return res.data;
  },

  // Upload & Analysis
  uploadEmail: async (file, onUploadProgress) => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await apiClient.post('/analyze/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      },
      onUploadProgress
    });
    return res.data;
  },

  // Load Demo Sample
  loadSampleEmail: async (sampleName) => {
    const res = await apiClient.post(`/analyze/sample/${sampleName}`);
    return res.data;
  },

  // Case Analysis Retrieval
  getCaseAnalysis: async (caseId) => {
    const res = await apiClient.get(`/analyze/case/${caseId}`);
    return res.data;
  },

  // Cases Management
  listCases: async (params = {}) => {
    const res = await apiClient.get('/cases', { params });
    return res.data;
  },

  getCase: async (caseId) => {
    const res = await apiClient.get(`/cases/${caseId}`);
    return res.data;
  },

  updateCase: async (caseId, updateData) => {
    const res = await apiClient.patch(`/cases/${caseId}`, updateData);
    return res.data;
  },

  deleteCase: async (caseId) => {
    const res = await apiClient.delete(`/cases/${caseId}`);
    return res.data;
  },

  // PDF Report Download URL
  getReportPdfUrl: (caseId) => {
    return `${API_BASE}/reports/${caseId}/pdf`;
  }
};

export default api;
