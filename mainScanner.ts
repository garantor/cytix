import axios, { AxiosResponse, AxiosError } from "axios";
import { config } from "./config";

// Define the VulnerabilityInterFace interface
interface VulnerabilityInterFace {
  title: string;
  description: string;
  url: string;
}

// Authenticate with the vulnerability scanner API and retrieve the access token
async function authenticateUser(): Promise<string | null> {
  try {
    const response = await axios.post(`${config.apiUrl}/auth`, {
      username: config.username,
      password: config.password,
    });

    return response.data.token;
  } catch (error) {
    // Check if the error is an AxiosError
    if ((error as AxiosError).isAxiosError) {
      const axiosError = error as AxiosError;

      // Provide more detailed error information if available
      if (axiosError.response) {
        // handle server returned error
        console.error(
          `Authentication failed with status code: ${axiosError.response.status}`
        );
      } else if (axiosError.request) {
        //handling error relating to request
        console.error("Authentication failed: No response from server");
      } else {
        console.error(`Authentication failed: ${axiosError.message}`);
      }
    } else {
      //other unspecified error
      console.error("Authentication failed:", error);
    }
    return null;
  }
}

// Run a scan for the provided URL and return the scan ID
async function scanUrl(token: string): Promise<string | null> {
  try {
    const response = await axios.post(
      `${config.apiUrl}/scan`,
      { url: config.scanUrl },
      { headers: { Authorization: `Bearer ${token}` } }
    );

    return response.data.scanId;
  } catch (error) {
    if ((error as AxiosError).isAxiosError) {
      const axiosError = error as AxiosError;
      if (axiosError.response) {
        // handle server returned error
        console.error(
          `Authentication failed with status code: ${axiosError.response.status}`
        );
      } else if (axiosError.request) {
        //handling error relating to request
        console.error("Authentication failed: No response from server");
      } else {
        console.error(`Authentication failed: ${axiosError.message}`);
      }
    } else {
      //other unspecified error
      console.error("Authentication failed:", error);
    }
    return null;
  }
}

// Get the scan results using the scan ID
async function getSingleScanResults(
  token: string,
  scanId: string
): Promise<AxiosResponse | null> {
  try {
    const response = await axios.get(
      `${config.apiUrl}/scans/${scanId}/results`,
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );

    return response;
  } catch (error) {
    console.error("Retrieving scan results failed:", error);
    return null;
  }
}

// Check the scan status using the scan ID
async function getStatusForScan(
  token: string,
  scanId: string
): Promise<AxiosResponse | null> {
  try {
    const response = await axios.get(
      `${config.apiUrl}/scans/${scanId}/results`,
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );

    return response;
  } catch (error) {
    if ((error as AxiosError).isAxiosError) {
      const axiosError = error as AxiosError;
      if (axiosError.response) {
        // handle server returned error
        console.error(
          `Authentication failed with status code: ${axiosError.response.status}`
        );
      } else if (axiosError.request) {
        //handling error relating to request
        console.error("Authentication failed: No response from server");
      } else {
        console.error(`Authentication failed: ${axiosError.message}`);
      }
    } else {
      //other unspecified error
      console.error("Authentication failed:", error);
    }
    return null;
  }
}
// Wait for the scan to complete before proceeding
async function waitForScanCompletion(
  token: string,
  scanId: string
): Promise<boolean> {
  const checkInterval = 10000; // 10 seconds

  return new Promise(async (resolve) => {
    const interval = setInterval(async () => {
      const response = await getStatusForScan(token, scanId);
      const statusCode = response?.status;

      console.log("this is the scan status code", statusCode);

      if (!statusCode) {
        clearInterval(interval);
        resolve(false);
      }

      if (statusCode === 200) {
        clearInterval(interval);
        resolve(true);
      } else if (statusCode !== 202) {
        clearInterval(interval);
        resolve(false);
      }
    }, checkInterval);
  });
}

// Main function to execute the script
async function executeScript() {
  const token = await authenticateUser();
  if (!token) {
    return;
  }

  //get the scan id
  const scanId = await scanUrl(token);
  if (!scanId) {
    return;
  }

  const scanCompleted = await waitForScanCompletion(token, scanId);
  if (!scanCompleted) {
    return;
  }

  const results = await getSingleScanResults(token, scanId);
  if (!results) {
    return;
  }

  const highRiskVulnerabilities: VulnerabilityInterFace[] =
    results.data.vulnerabilities
      .filter((vuln: any) => vuln.severity === "High") // check for severity of issue
      .map((vuln: any) => ({
        title: vuln.title,
        description: vuln.description,
        url: vuln.url,
      }));

  console.log(highRiskVulnerabilities);
}

executeScript();

//Test would be included at a later day
