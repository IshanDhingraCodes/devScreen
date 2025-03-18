import { boolean, z } from "zod";

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8, {
    message: "Password must contain minimum 8 characters",
  }),
});

export const signUpSchema = z
  .object({
    name: z.string().max(30),
    email: z.string().email(),
    password: z.string().min(8, {
      message: "Password must contain minimum 8 characters",
    }),
    confirmPassword: z.string().min(8, {
      message: "Password must contain minimum 8 characters",
    }),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Password must be same",
    path: ["confirmPassword"],
  });
