import { NextFunction, Request, Response } from "express";
import httpStatus from "http-status";
import config from "../../config";
import { Secret } from "jsonwebtoken";
import ApiError from "../../errors/api_error";
import { JwtHelpers } from "../../utils/jwt.helper";
import { User } from "../modules/user/user.model";
import { TokenBlacklist } from "../modules/auth/tokenBlacklist.model";
import { USER_STATUS } from "../../enums/user_status";

type JwtVerifiedUser = {
  _id: string;
  tokenVersion?: number;
  role?: string;
};

const auth = (...requiredRole: string[]) =>
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const authHeader = (req.headers.authorization || "") as string;

      // Support both header-based and cookie-based tokens.
      const bearerToken = authHeader.startsWith("Bearer ")
        ? authHeader.slice(7).trim()
        : "";

      const cookieToken = (req as any).cookies?.accessToken || (req as any).cookies?.token;

      const token = bearerToken || cookieToken || "";

      if (!token) {
        throw new ApiError(
          httpStatus.UNAUTHORIZED,
          "You are not authorized to access"
        );
      }

      const verifiedUser = JwtHelpers.verifyToken(
        token,
        config.jwt.secret as Secret
      ) as unknown as JwtVerifiedUser;

      // Ensure this exact token string is not blacklisted.
      const isBlacklisted = await TokenBlacklist.findOne({ token });
      if (isBlacklisted) {
        throw new ApiError(
          httpStatus.UNAUTHORIZED,
          "Token has been revoked. Please log in again."
        );
      }

      const user = await User.findById(verifiedUser?._id);
      if (!user) {
        throw new ApiError(httpStatus.UNAUTHORIZED, "User not found");
      }

      // Token invalidation check (e.g., on refresh/logout via tokenVersion).
      if (
        user.tokenVersion !== undefined &&
        verifiedUser?.tokenVersion !== undefined &&
        user.tokenVersion !== verifiedUser.tokenVersion
      ) {
        throw new ApiError(
          httpStatus.UNAUTHORIZED,
          "Token is invalid or expired"
        );
      }

      // Status check
      if (user.status !== USER_STATUS.ACTIVE) {
        throw new ApiError(
          httpStatus.FORBIDDEN,
          "Your account is not active"
        );
      }

      // Role check (if roles are required)
      if (
        requiredRole.length &&
        !requiredRole.includes(verifiedUser?.role as string)
      ) {
        throw new ApiError(httpStatus.FORBIDDEN, "Forbidden");
      }

      (req as any).user = user;
      return next();
    } catch (err) {
      return next(err);
    }
  };

export default auth;

