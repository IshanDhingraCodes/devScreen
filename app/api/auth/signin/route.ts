import { db } from "@/lib/db";
import { loginSchema } from "@/schema/auth.schema";
import bcrypt from "bcryptjs";
import { NextRequest, NextResponse } from "next/server";
import jwt from "jsonwebtoken";

const jwtSecret = process.env.JWT_SECRET!;

export async function POST(req: NextRequest) {
  try {
    const userFormData = await req.formData();

    const email = userFormData.get("email");

    const password = userFormData.get("password");

    const parsedData = loginSchema.safeParse({ email, password });

    if (!parsedData.success) {
      return NextResponse.json({
        message: "Invalid Data",
        success: false,
        error: parsedData.error,
      });
    }

    const { email: parsedEmail, password: parsedPassword } = parsedData.data;

    const existingUser = await db.user.findUnique({
      where: {
        email: parsedEmail,
      },
    });

    if (!existingUser) {
      return NextResponse.json(
        {
          message: "User not found",
          success: false,
        },
        {
          status: 401,
        }
      );
    }

    if (!existingUser.emailVerified) {
      //todo send verification email
      return NextResponse.json(
        {
          message: "Not verified",
          success: false,
        },
        {
          status: 401,
        }
      );
    }

    const isMatched = await bcrypt.compare(
      parsedPassword,
      existingUser.password
    );

    if (!isMatched) {
      return NextResponse.json(
        {
          message: "Invalid Crediential",
          success: false,
        },
        {
          status: 401,
        }
      );
    }

    const token = jwt.sign(
      { userId: existingUser.id, email: existingUser.email },
      jwtSecret,
      { expiresIn: "7d" }
    );

    const response = NextResponse.json({
      message: "Login Successful",
      success: true,
    });

    response.cookies.set({
      name: "authToken",
      value: token,
      maxAge: 7 * 24 * 60 * 60 * 60 * 1000,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    });

    return response;
  } catch (error) {
    return NextResponse.json(
      {
        success: false,
      },
      {
        status: 500,
      }
    );
  }
}
