import { Hono } from "hono";
import { AuthModule } from "../core/users/users.module";

const AppRouter = new Hono();
const authModule = new AuthModule();

AppRouter.get("/", (c) => c.text("Welcome to the API!"));
AppRouter.route("/auth", authModule.router);

export default AppRouter;
