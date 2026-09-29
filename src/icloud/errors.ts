/** Error types. Callers branch on these classes, never on message text. */

export class ICloudError extends Error {
  override name = "ICloudError";
}

/** A non-success response, or an error payload inside a 200. */
export class ApiError extends ICloudError {
  override name = "ApiError";
  readonly status: number | undefined;
  readonly code: string | number | undefined;
  constructor(message: string, status?: number, code?: string | number) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/** Sign-in succeeded but Apple wants a two-factor code before trusting this session. */
export class TwoFactorRequiredError extends ICloudError {
  override name = "TwoFactorRequiredError";
}

/**
 * The session is no longer accepted (421, 450) and must be re-established.
 * Distinct from a network failure, which says nothing about the session.
 */
export class AuthRequiredError extends ICloudError {
  override name = "AuthRequiredError";
}

/** Apple rejected the Apple ID or password. */
export class FailedLoginError extends ICloudError {
  override name = "FailedLoginError";
}

/** iCloud Drive (or another service) is not enabled for this account. */
export class ServiceNotActivatedError extends ApiError {
  override name = "ServiceNotActivatedError";
}

/** The trusted-device prompt could not be started. */
export class TrustedDevicePromptError extends ICloudError {
  override name = "TrustedDevicePromptError";
}

/** The trusted-device verification failed for a reason other than a wrong code. */
export class TrustedDeviceVerificationError extends ICloudError {
  override name = "TrustedDeviceVerificationError";
}

export class NoTrustedPhoneNumberError extends ICloudError {
  override name = "NoTrustedPhoneNumberError";
}

/** Apple requires accepting new iCloud terms, which must be done on icloud.com. */
export class TermsAcceptanceRequiredError extends ICloudError {
  override name = "TermsAcceptanceRequiredError";
}
