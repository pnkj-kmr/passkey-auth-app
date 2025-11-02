import axios from "axios";

// Function to get CSRF token from cookie
function getCsrfToken(): string | null {
  const name = "csrftoken";
  const cookies = document.cookie.split(";");
  for (let cookie of cookies) {
    const [key, value] = cookie.trim().split("=");
    if (key === name) {
      return decodeURIComponent(value);
    }
  }
  return null;
}

// Fetch CSRF token on app initialization
let csrfTokenPromise: Promise<string> | null = null;

async function fetchCsrfToken(): Promise<string> {
  if (!csrfTokenPromise) {
    csrfTokenPromise = axios
      .get("/api/auth/csrf-token/", { withCredentials: true })
      .then((response) => response.data.csrfToken);
  }
  return csrfTokenPromise;
}

const api = axios.create({
  baseURL: "/api",
  withCredentials: true,
  headers: {
    "Content-Type": "application/json",
  },
});

// Add CSRF token to all POST, PUT, PATCH, DELETE requests
api.interceptors.request.use(async (config) => {
  if (
    ["post", "put", "patch", "delete"].includes(
      config.method?.toLowerCase() || ""
    )
  ) {
    // Try to get from cookie first
    let token = getCsrfToken();

    // If not in cookie, fetch it
    if (!token) {
      token = await fetchCsrfToken();
    }

    if (token) {
      config.headers["X-CSRFToken"] = token;
    }
  }
  return config;
});

export interface User {
  id: number;
  username: string;
  email: string;
}

export interface RegisterStartResponse {
  challenge: string;
  rp: {
    id: string;
    name: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: Array<{ alg: number; type: string }>;
  authenticatorSelection: {
    authenticatorAttachment: string | null;
    userVerification: string;
    requireResidentKey: boolean;
  };
  timeout: number;
  attestation: string;
}

export interface LoginStartResponse {
  challenge: string;
  allowCredentials: Array<{
    id: string;
    type: string;
  }>;
  timeout: number;
  userVerification: string;
  rpId: string;
}

export interface AuthResponse {
  message: string;
  user: User;
}

// Initialize CSRF token on module load
fetchCsrfToken().catch(() => {
  // Silently fail - will fetch when needed
});

export const authApi = {
  registerStart: async (
    username: string,
    email: string
  ): Promise<RegisterStartResponse> => {
    const response = await api.post<RegisterStartResponse>(
      "/auth/register/start/",
      {
        username,
        email,
      }
    );
    return response.data;
  },

  registerComplete: async (
    credential: any,
    challenge: string
  ): Promise<AuthResponse> => {
    const response = await api.post<AuthResponse>("/auth/register/complete/", {
      credential,
      challenge,
    });
    return response.data;
  },

  loginStart: async (username: string): Promise<LoginStartResponse> => {
    const response = await api.post<LoginStartResponse>("/auth/login/start/", {
      username,
    });
    return response.data;
  },

  loginComplete: async (
    credential: any,
    challenge: string
  ): Promise<AuthResponse> => {
    const response = await api.post<AuthResponse>("/auth/login/complete/", {
      credential,
      challenge,
    });
    return response.data;
  },

  getUserInfo: async (): Promise<User> => {
    const response = await api.get<User>("/auth/user/");
    return response.data;
  },

  logout: async (): Promise<void> => {
    await api.post("/auth/logout/");
  },
};
