import { prismaClient } from "@/lib/prisma-client";
import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";
import GitHubProvider from "next-auth/providers/github";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import { refreshAccessToken } from "./refresh-access-token";

declare module "next-auth/jwt" {
	interface JWT {
		id: string;
		accessTokenExpires?: number;
		refreshToken?: string;
	}
}

declare module "next-auth" {
	interface Session {
		user: {
			id: string;
		};
		accessTokenExpires?: number;
	}

	interface User {
		id: string;
		refreshToken?: string;
	}
}

const nextAuthOptions: NextAuthOptions = {
	providers: [
		CredentialsProvider({
			name: "credentials",
			credentials: {
				username: {
					label: "username",
					type: "text",
				},
				password: {
					label: "password",
					type: "password",
				},
			},

			async authorize(credentials) {
				if (!(credentials?.username && credentials?.password)) {
					return null;
				}

				const user = await prismaClient.user.findFirst({
					where: {
						username: credentials?.username,
					},
				});

				if (!user) {
					return null;
				}

				if (!user.password) {
					return null;
				}

				const isValid = await argon2.verify(
					user.password,
					credentials?.password,
				);

				if (!isValid) {
					return null;
				}

				const refreshToken = jwt.sign(
					{ id: user.id },
					process.env.JWT_SECRET || "",
					{ expiresIn: "30d" },
				);

				await prismaClient.user.update({
					where: { id: user.id },
					data: { refreshToken },
				});

				return {
					id: String(user.id),
					refreshToken,
				};
			},
		}),
		GoogleProvider({
			clientId: process.env.GOOGLE_CLIENT_ID!,
			clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
		}),
		GitHubProvider({
			clientId: process.env.GITHUB_CLIENT_ID!,
			clientSecret: process.env.GITHUB_CLIENT_SECRET!,
		}),
	],
	pages: {
		signIn: "/auth",
	},
	callbacks: {
		async signIn({ account, profile }) {
			if (account?.provider === "google" || account?.provider === "github") {
				const newId = profile?.sub;
				const email = profile?.email;

				let existingUser = await prismaClient.user.findFirst({
					where: { OR: [{ providerId: newId }, { email }] },
				});

				if (!existingUser) {
					existingUser = await prismaClient.user.create({
						data: {
							email: email!,
							name: profile?.name!,
							image: profile?.image || "",
							providerId: newId!,
						},
					});
				}

				return true;
			}

			return true;
		},
		jwt({ token, user }) {
			if (user) {
				token.id = user.id;
				token.accessTokenExpires = Date.now() + 15 * 60 * 1000;
				token.refreshToken = user.refreshToken;
			}

			if (token.accessTokenExpires && Date.now() < token.accessTokenExpires)
				return token;

			return refreshAccessToken(token);
		},
		session({ session, token }) {
			session.user = {
				id: token.id,
			};
			session.accessTokenExpires = token.accessTokenExpires || 0;

			return session;
		},
	},
};

export { nextAuthOptions };
