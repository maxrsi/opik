import axiosInstance from "@/api/api";

/** Fired when the Opik API rejects the session, so the preloader re-checks /auth/api/me and shows the login page. */
export const UNAUTHORIZED_EVENT = "selfhosted:unauthorized";

let installed = false;

const install = () => {
  if (installed) {
    return;
  }
  installed = true;
  axiosInstance.interceptors.response.use(undefined, (error) => {
    if (error?.response?.status === 401) {
      window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    }
    return Promise.reject(error);
  });
};

install();

export default install;
