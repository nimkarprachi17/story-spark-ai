import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import { User } from "../user/user.model";
import { AuthModel } from "./auth.interface";
import { IUser } from "../user/user.interface";
import config from "../../../config";
import redis from "../../../app/utils/redis.client";
import ApiError from "../../../errors/api_error";
import httpStatus from "http-status";
import { RefreshSession } from "./refresh_session.model";

// ─── Helpers ───────────────────────────────────────────────────────────────────

const googleClient = new OAuth2Client(config.google_client_id);

const REFRESH_TOKEN_PREFIX = "refresh:";

/** Sign a short-lived access token */
const signAccessToken = (payload: object): string =>
  jwt.sign(payload, config.jwt.secret, {
    expiresIn: (config.jwt.expires_in as any) ?? "15m",
  });

/** Sign a long-lived refresh token */
const signRefreshToken = (payload: object): string =>
  jwt.sign(payload, config.jwt.refresh_secret, {
    expiresIn: (config.jwt.refresh_expires_in as any) ?? "30d",
  });

/** Build the JWT payload from a user document */
const buildTokenPayload = (user: any) => ({
  userId: user._id.toString(),
  email: user.email,
  name: user.name,
  role: user.role,
  subscriptionType: user.subscriptionType,
  postsCount: user.postsCount,
  avatar: user.profile?.avatar ?? "",
  tokenVersion: user.tokenVersion ?? 0,
});

/** Store refresh token in Redis with TTL matching token expiry (30 days) */
const storeRefreshToken = async (userId: string, token: string) => {
  const ttl = 30 * 24 * 60 * 60; // 30 days in seconds
  await redis.set(`${REFRESH_TOKEN_PREFIX}${userId}`, token, "EX", ttl);
};

/** Remove refresh token from Redis */
const deleteRefreshToken = async (userId: string) => {
  await redis.del(`${REFRESH_TOKEN_PREFIX}${userId}`);
};

// ─── Service ───────────────────────────────────────────────────────────────────

const login = async (payload: AuthModel) => {
  const { email, password } = payload;

  const user = await User.findOne({ email }).select("+password");
  if (!user) {
    throw new ApiError(httpStatus.UNAUTHORIZED, "Invalid email or password.");
  }

  if (!user.password) {
    throw new ApiError(
      httpStatus.UNAUTHORIZED,
      "This account uses Google login. Please sign in with Google."
    );
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    throw new ApiError(httpStatus.UNAUTHORIZED, "Invalid email or password.");
  }

  if (user.status === "blocked") {
    throw new ApiError(httpStatus.FORBIDDEN, "Your account has been blocked.");
  }

  const tokenPayload = buildTokenPayload(user);
  const accessToken = signAccessToken(tokenPayload);
  const refreshToken = signRefreshToken({ userId: user._id.toString() });

  await storeRefreshToken(user._id.toString(), refreshToken);

  return { accessToken, refreshToken };
};

const register = async (payload: IUser) => {
  const existing = await User.findOne({ email: payload.email });
  if (existing) {
    throw new ApiError(httpStatus.CONFLICT, "Email is already registered.");
  }

  const user = await User.create(payload);

  const tokenPayload = buildTokenPayload(user);
  const accessToken = signAccessToken(tokenPayload);
  const refreshToken = signRefreshToken({ userId: user._id.toString() });

  await storeRefreshToken(user._id.toString(), refreshToken);

  return { accessToken, refreshToken };
};

const refreshToken = async (token: string) => {
  if (!token) {
    throw new ApiError(httpStatus.UNAUTHORIZED, "Refresh token is required.");
  }

  let decoded: any;
  try {
    decoded = jwt.verify(token, config.jwt.refresh_secret);
  } catch {
    throw new ApiError(httpStatus.UNAUTHORIZED, "Invalid or expired refresh token.");
  }

  const userId = decoded.userId;

  // Validate against Redis — ensures the token hasn't been rotated/invalidated
  const stored = await redis.get(`${REFRESH_TOKEN_PREFIX}${userId}`);
  if (!stored || stored !== token) {
    throw new ApiError(httpStatus.UNAUTHORIZED, "Refresh token has been revoked.");
  }

  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError(httpStatus.UNAUTHORIZED, "User not found.");
  }

  if (user.status === "blocked") {
    throw new ApiError(httpStatus.FORBIDDEN, "Your account has been blocked.");
  }

  // Rotate: issue new pair, invalidate old refresh token
  const tokenPayload = buildTokenPayload(user);
  const accessToken = signAccessToken(tokenPayload);
  const newRefreshToken = signRefreshToken({ userId: user._id.toString() });

  await storeRefreshToken(userId, newRefreshToken);

  return { accessToken, refreshToken: newRefreshToken };
};

const logout = async (token: string) => {
  if (!token) return;

  try {
    const decoded: any = jwt.verify(token, config.jwt.refresh_secret);
    await deleteRefreshToken(decoded.userId);
  } catch {
    // Token already invalid — nothing to clean up
  }
};

const googleLogin = async (payload: { credential: string }) => {
  const { credential } = payload;

  if (!credential) {
    throw new ApiError(httpStatus.BAD_REQUEST, "Google credential is required.");
  }

  let ticket: any;
  try {
    ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: config.google_client_id,
    });
  } catch {
    throw new ApiError(httpStatus.UNAUTHORIZED, "Invalid Google credential.");
  }

  const googlePayload = ticket.getPayload();
  if (!googlePayload?.email) {
    throw new ApiError(httpStatus.UNAUTHORIZED, "Could not retrieve email from Google.");
  }

  let user = await User.findOne({ email: googlePayload.email });

  if (!user) {
    // Auto-register Google users
    user = await User.create({
      email: googlePayload.email,
      name: googlePayload.name ?? googlePayload.email.split("@")[0],
      role: "user",
      status: "active",
      subscriptionType: "free",
      postsCount: 0,
      followers: [],
      following: [],
      posts: [],
      isApplyForWriter: false,
      profile: {
        avatar: googlePayload.picture ?? "",
        bio: "",
        social: {
          facebook: "",
          twitter: "",
          linkedin: "",
          instagram: "",
          github: "",
          discord: "",
        },
      },
      writingGoals: { dailyWordCount: 0, weeklyWordCount: 0 },
      gamification: {
        xp: 0,
        level: 1,
        streak: 0,
        lastActiveDate: null,
        badges: [],
      },
      writingStreak: {
        currentStreak: 0,
        longestStreak: 0,
        lastActiveDate: null,
        totalWritingDays: 0,
      },
    });
  }

  if (user.status === "blocked") {
    throw new ApiError(httpStatus.FORBIDDEN, "Your account has been blocked.");
  }

  const tokenPayload = buildTokenPayload(user);
  const accessToken = signAccessToken(tokenPayload);
  const refreshToken = signRefreshToken({ userId: user._id.toString() });

  await storeRefreshToken(user._id.toString(), refreshToken);

  return { accessToken, refreshToken };
};

const changePassword = async (
  userInfo: { userId: string; tokenVersion?: number },
  payload: { oldPassword: string; newPassword: string }
) => {
  const { oldPassword, newPassword } = payload;

  const user = await User.findById(userInfo.userId).select("+password");
  if (!user) {
    throw new ApiError(httpStatus.NOT_FOUND, "User not found.");
  }

  if (!user.password) {
    throw new ApiError(
      httpStatus.BAD_REQUEST,
      "Password change is not available for Google accounts."
    );
  }

  const isMatch = await bcrypt.compare(oldPassword, user.password);
  if (!isMatch) {
    throw new ApiError(httpStatus.UNAUTHORIZED, "Old password is incorrect.");
  }

  user.password = newPassword; // pre-save hook will hash it
  user.tokenVersion = (user.tokenVersion ?? 0) + 1; // invalidate all existing sessions
  await user.save();

  // Revoke refresh token — user must log in again
  await deleteRefreshToken(user._id.toString());
};

const forgotPassword = async (email: string) => {
  const user = await User.findOne({ email });
  // Always return success to prevent email enumeration
  if (!user) return null;

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const ttl = 10 * 60; // 10 minutes

  await redis.set(`otp:${email}`, otp, "EX", ttl);

  // TODO: wire up email sending (nodemailer / SendGrid / etc.)
  // await sendEmail({ to: email, subject: "Your OTP", text: `Your OTP is ${otp}` });

  return null;
};

const resetPassword = async (payload: {
  email: string;
  password: string;
  confirmPassword: string;
  verificationToken: string;
}) => {
  const { email, password, confirmPassword, verificationToken } = payload;

  if (password !== confirmPassword) {
    throw new ApiError(httpStatus.BAD_REQUEST, "Passwords do not match.");
  }

  const storedOtp = await redis.get(`otp:${email}`);
  if (!storedOtp || storedOtp !== verificationToken) {
    throw new ApiError(httpStatus.BAD_REQUEST, "Invalid or expired OTP.");
  }

  const user = await User.findOne({ email }).select("+password");
  if (!user) {
    throw new ApiError(httpStatus.NOT_FOUND, "User not found.");
  }

  user.password = password; // pre-save hook hashes it
  user.tokenVersion = (user.tokenVersion ?? 0) + 1;
  await user.save();

  // Clear OTP and any existing refresh token
  await redis.del(`otp:${email}`);
  await deleteRefreshToken(user._id.toString());

  const tokenPayload = buildTokenPayload(user);
  const accessToken = signAccessToken(tokenPayload);
  const refreshToken = signRefreshToken({ userId: user._id.toString() });

  await storeRefreshToken(user._id.toString(), refreshToken);

  return { accessToken, refreshToken };
};

// ─── Exports ───────────────────────────────────────────────────────────────────

export const AuthService = {
  login,
  register,
  refreshToken,
  logout,
  googleLogin,
  changePassword,
  forgotPassword,
  resetPassword,
};