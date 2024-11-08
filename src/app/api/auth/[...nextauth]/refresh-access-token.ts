import type { JWT } from "next-auth/jwt";
import jwt from "jsonwebtoken";
import { prismaClient } from "@/lib/prisma-client";

export async function refreshAccessToken(token: JWT) {
	try {
		const newAccessToken = jwt.sign(
			{ id: token.id, role: token.role },
			process.env.JWT_SECRET || "",
			{ expiresIn: "15m" },
		);

		const newRefreshToken = jwt.sign(
			{ id: token.id },
			process.env.JWT_SECRET || "",
			{ expiresIn: "30d" },
		);

		await prismaClient.user.update({
			where: { id: Number(token.id) },
			data: { refreshToken: newRefreshToken },
		});

		return {
			...token,
			accessToken: newAccessToken,
			accessTokenExpires: Date.now() + 15 * 60 * 1000,
			refreshToken: newRefreshToken,
		};
	} catch {
		return { ...token, error: "RefreshAccessTokenError" };
	}
}
