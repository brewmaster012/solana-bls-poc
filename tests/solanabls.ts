import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Solanabls } from "../target/types/solanabls";
import { ComputeBudgetProgram } from "@solana/web3.js";

describe("solanabls", () => {
  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.AnchorProvider.env());

  const program = anchor.workspace.Solanabls as Program<Solanabls>;
  const conn = anchor.getProvider().connection;

  it("Is initialized!", async () => {
    // Add your test here.
    const tx = await program.methods.initialize().rpc();
    console.log("Your transaction signature", tx);
  });

  it("Compute", async () => {
    const tx = await program.methods
      .compute(new anchor.BN(40))
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({ units: 10_000_000 }),
      ])
      .rpc({ commitment: "confirmed" });
    console.log("Your transaction signature", tx);
    const parsed = await conn.getParsedTransaction(tx, {
      commitment: "confirmed",
    });
    console.log(parsed);
  });
});
