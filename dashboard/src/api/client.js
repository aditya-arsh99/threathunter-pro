import axios from "axios";

const api = axios.create({
  baseURL: "/api",
  timeout: 10000,
});

export const fetchEventStats  = ()              => api.get("/events/stats").then(r => r.data);
export const fetchAlertStats  = ()              => api.get("/alerts/stats").then(r => r.data);
export const fetchAlerts      = (params = {})   => api.get("/alerts",          { params }).then(r => r.data);
export const fetchNetworkEvents = (params = {}) => api.get("/events/network",  { params }).then(r => r.data);
export const fetchWindowsEvents = (params = {}) => api.get("/events/windows",  { params }).then(r => r.data);
export const fetchHealth      = ()              => api.get("/health").then(r => r.data);
export const acknowledgeAlert = (id, body)      => api.patch(`/alerts/${id}/acknowledge`, body).then(r => r.data);
export const dismissAlert     = (id)            => api.delete(`/alerts/${id}`).then(r => r.data);
