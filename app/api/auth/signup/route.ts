import { signUpSchema } from "@/schema/auth.validation";
import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { db } from "@/lib/db";

export async function POST(req: NextRequest) {
  try {
    const formData = await req.formData();

    const data = Object.fromEntries(formData.entries());

    const parsedData = signUpSchema.safeParse(data);

    if (!parsedData.success) {
      return NextResponse.json(
        {
          message: "Invalid data",
          success: false,
          error: parsedData.error,
        },
        {
          status: 401,
        }
      );
    }

    const { name, email, password } = parsedData.data;

    const existingUser = await db.user.findUnique({
      where: {
        email,
      },
    });

    if (existingUser) {
      return NextResponse.json(
        {
          message: "User already Exist ",
          success: false,
        },
        {
          status: 401,
        }
      );
    }

    const hashedPassword = bcrypt.hashSync(password, 10);

    const user = await db.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    //todo send verification token

    return NextResponse.json({
      message: "User created",
      success: true,
      user,
    });
  } catch (error) {
    return NextResponse.json(
      {
        message: "Something went wrong",

        success: false,
      },
      {
        status: 500,
      }
    );
  }
}
