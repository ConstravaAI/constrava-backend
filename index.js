import express from "express";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;

app.get("/", (req, res) => {
  res.send("Backend is running ✅");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
