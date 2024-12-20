import {
  clerkClient,
  clerkMiddleware,
  createRouteMatcher,
} from "@clerk/nextjs/server";
import { NextRequest, NextResponse } from "next/server";

const ispublicRoutes = createRouteMatcher([
  "/",
  "/api/webhook/register",
  "/sign-in",
  "/sign-up",
]);

export default clerkMiddleware(async (auth, request: NextRequest) => {
  const { userId } = await auth();
  if (!userId && !ispublicRoutes(request)) {
    return NextResponse.redirect(new URL("/sign-in", request.url));
  }
  if (userId) {
    try {
      const client = await clerkClient();

      const user = await client.users.getUser(userId); // Fetch user data from Clerk
      const role = user.publicMetadata.role as string | undefined;

      // Admin role redirection logic
      if (role === "admin" && request.nextUrl.pathname === "/dashboard") {
        return NextResponse.redirect(new URL("/admin/dashboard", request.url));
      }

      // Prevent non-admin users from accessing admin routes
      if (role !== "admin" && request.nextUrl.pathname.startsWith("/admin")) {
        return NextResponse.redirect(new URL("/dashboard", request.url));
      }

      // Redirect authenticated users trying to access public routes
      if (ispublicRoutes(request)) {
        return NextResponse.redirect(
          new URL(
            role === "admin" ? "/admin/dashboard" : "/dashboard",
            request.url
          )
        );
      }
    } catch (error) {
      console.error("Error fetching user data from Clerk:", error);
      return NextResponse.redirect(new URL("/error", request.url));
    }
  }
});

export const config = {
  matcher: ["/((?!.+\\.[\\w]+$|_next).*)", "/", "/(api|trpc)(.*)"],
};
