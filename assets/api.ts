const API_BASE = "http://127.0.0.1:5000/apidocs/#/";

interface CountyData {
  registeredVoters: number;
  eligibleVoters: number;
  pollingStations: number;
  lastUpdated: string;
  constituencies: { name: string; voters: number }[];
}

interface PollingStation {
  id: number;
  name: string;
  county: string;
  location: string;
  coordinates: { latitude: number; longitude: number };
  registeredVoters: number;
  eligibleVoters: number;
  contact: string;
}

export const getCounties = async (): Promise<string[]> => {
  const response = await fetch(`${API_BASE}/api/counties`);
  return await response.json();
};

export const getCountyStats = async (countyName: string): Promise<CountyData> => {
  const response = await fetch(`${API_BASE}/api/county/${encodeURIComponent(countyName)}`);
  if (!response.ok) throw new Error("County not found");
  return await response.json();
};

export const getPollingStations = async (options?: {
  county?: string;
  limit?: number;
}): Promise<PollingStation[]> => {
  const params = new URLSearchParams();
  if (options?.county) params.append('county', options.county);
  if (options?.limit) params.append('limit', options.limit.toString());
  
  const response = await fetch(`${API_BASE}/api/polling-stations?${params}`);
  return await response.json();
};