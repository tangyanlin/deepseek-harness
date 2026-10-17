import crypto from "node:crypto";
import express from "express";
import nodemailer from "nodemailer";

const app = express();

const webhookSecret = process.env.GITHUB_WEBHOOK_SECRET;

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT ?? 465),
  secure: process.env.SMTP_SECURE !== "false",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD,
  },
});

function verifySignature(payload, signature) {
  if (!signature || !webhookSecret) {
    return false;
  }

  const expected = `sha256=${crypto
    .createHmac("sha256", webhookSecret)
    .update(payload)
    .digest("hex")}`;

  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected),
  );
}

app.post(
  "/webhooks/github",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const signature = req.headers["x-hub-signature-256"];

    if (!verifySignature(req.body, signature)) {
      res.status(401).send("Invalid signature");
      return;
    }

    const event = JSON.parse(req.body.toString("utf8"));

    // GitHub 的 pull_request.closed 事件中，
    // merged === true 才表示 Pull Request 实际完成了合并。
    if (
      req.headers["x-github-event"] === "pull_request" &&
      event.action === "closed" &&
      event.pull_request?.merged === true
    ) {
      const repository = event.repository.full_name;
      const pullRequest = event.pull_request;
      const sender = event.sender.login;

      await mailer.sendMail({
        from: process.env.MAIL_FROM,
        to: "tangyanlin@360.cn",
        subject: `[GitHub] ${repository} 的 Pull Request 已合并`,
        text: [
          `仓库：${repository}`,
          `标题：${pullRequest.title}`,
          `编号：#${pullRequest.number}`,
          `合并分支：${pullRequest.base.ref}`,
          `来源分支：${pullRequest.head.ref}`,
          `合并提交：${pullRequest.merge_commit_sha}`,
          `操作人：${sender}`,
          `链接：${pullRequest.html_url}`,
        ].join("\n"),
      });
    }

    res.sendStatus(200);
  },
);

app.listen(process.env.PORT ?? 3000, () => {
  console.log("GitHub webhook server is running");
});
