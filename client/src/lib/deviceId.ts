/**
 * Device identification for multi-device terminal sessions
 *
 * Generates and persists a unique device identifier to enable
 * users to access the same terminals from multiple devices.
 */

const DEVICE_ID_KEY = 'triterm_device_id';
const DEVICE_NAME_KEY = 'triterm_device_name';

/**
 * Generate a random device ID
 */
function generateDeviceId(): string {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 15);
  return `device-${timestamp}-${random}`;
}

/**
 * Get the default device name based on browser/OS info
 */
function getDefaultDeviceName(): string {
  const ua = navigator.userAgent;
  let deviceType = 'Unknown Device';

  // Detect device type
  if (/Mobile|Android|iPhone|iPad|iPod/i.test(ua)) {
    if (/iPad/i.test(ua)) {
      deviceType = 'iPad';
    } else if (/iPhone/i.test(ua)) {
      deviceType = 'iPhone';
    } else if (/Android/i.test(ua)) {
      deviceType = 'Android Device';
    } else {
      deviceType = 'Mobile Device';
    }
  } else if (/Mac/i.test(ua)) {
    deviceType = 'Mac';
  } else if (/Win/i.test(ua)) {
    deviceType = 'Windows PC';
  } else if (/Linux/i.test(ua)) {
    deviceType = 'Linux PC';
  } else {
    deviceType = 'Desktop';
  }

  // Add browser info
  let browser = '';
  if (/Chrome/i.test(ua) && !/Edg/i.test(ua)) {
    browser = 'Chrome';
  } else if (/Safari/i.test(ua) && !/Chrome/i.test(ua)) {
    browser = 'Safari';
  } else if (/Firefox/i.test(ua)) {
    browser = 'Firefox';
  } else if (/Edg/i.test(ua)) {
    browser = 'Edge';
  }

  return browser ? `${deviceType} (${browser})` : deviceType;
}

/**
 * Get or create a device ID
 */
export function getDeviceId(): string {
  try {
    let deviceId = localStorage.getItem(DEVICE_ID_KEY);

    if (!deviceId) {
      deviceId = generateDeviceId();
      localStorage.setItem(DEVICE_ID_KEY, deviceId);
      console.log('[DeviceID] Generated new device ID:', deviceId);
    }

    return deviceId;
  } catch (error) {
    console.error('[DeviceID] Failed to get/create device ID:', error);
    // Fallback to session-only ID if localStorage fails
    return generateDeviceId();
  }
}

/**
 * Get or create a device name
 */
export function getDeviceName(): string {
  try {
    let deviceName = localStorage.getItem(DEVICE_NAME_KEY);

    if (!deviceName) {
      deviceName = getDefaultDeviceName();
      localStorage.setItem(DEVICE_NAME_KEY, deviceName);
      console.log('[DeviceID] Generated default device name:', deviceName);
    }

    return deviceName;
  } catch (error) {
    console.error('[DeviceID] Failed to get/create device name:', error);
    return getDefaultDeviceName();
  }
}

/**
 * Set a custom device name
 */
export function setDeviceName(name: string): void {
  try {
    localStorage.setItem(DEVICE_NAME_KEY, name);
    console.log('[DeviceID] Updated device name:', name);
  } catch (error) {
    console.error('[DeviceID] Failed to set device name:', error);
  }
}

/**
 * Reset device identification (useful for testing or troubleshooting)
 */
export function resetDeviceId(): void {
  try {
    localStorage.removeItem(DEVICE_ID_KEY);
    localStorage.removeItem(DEVICE_NAME_KEY);
    console.log('[DeviceID] Device identification reset');
  } catch (error) {
    console.error('[DeviceID] Failed to reset device ID:', error);
  }
}

/**
 * Get device info for socket connection
 */
export function getDeviceInfo(): { deviceId: string; deviceName: string } {
  return {
    deviceId: getDeviceId(),
    deviceName: getDeviceName(),
  };
}
