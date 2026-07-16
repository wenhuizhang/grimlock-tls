(* Grimlock authorization — machine-checked core (Coq 8.20).

   Proves, with NO axioms and NO Admitted:
     - transcript_injective  : the binding transcript is injective (model L2)
     - covered_monotone      : more grants never remove a permission (T4)
     - covered_attenuation   : a delegate holding a subset grants no more (multi-hop)
     - no_grant_denied       : no covering grant => denied (fail-closed)
     - covered_refine        : a grant permits all refinements under it

   Crypto primitives (quote/exporter/signature/hash security) are the stated
   assumptions of docs/threat-model.md §6 and are NOT proved here — this
   development discharges exactly the parts that need no such assumption. *)

From Coq Require Import List Arith Lia.
Import ListNotations.

(* ================================================================= *)
(*  Transcript injectivity (internal/authz)                          *)
(* ================================================================= *)
(*  Bytes are an arbitrary alphabet; the length prefix is a single    *)
(*  self-delimiting symbol. The real code writes a fixed-width 4-byte  *)
(*  big-endian length — the injectivity argument is identical: what    *)
(*  matters is that the length is a self-delimiting injective code.    *)

Definition byte  := nat.
Definition bytes := list byte.

(* length-prefixed value: write the length, then the bytes. *)
Definition lp (v : bytes) : bytes := length v :: v.

(* From equal-length prefixes of equal concatenations, the prefixes and
   the remainders are equal. *)
Lemma app_split :
  forall (a b x y : bytes),
    length a = length b -> a ++ x = b ++ y -> a = b /\ x = y.
Proof.
  induction a as [|ha ta IH]; intros [|hb tb] x y Hlen Happ; simpl in *.
  - split; [reflexivity | assumption].
  - discriminate Hlen.
  - discriminate Hlen.
  - injection Happ as Hh Happ'. injection Hlen as Hlen'.
    destruct (IH tb x y Hlen' Happ') as [Hab Hxy]. subst. auto.
Qed.

Lemma lp_app_inj :
  forall (a b x y : bytes), lp a ++ x = lp b ++ y -> a = b /\ x = y.
Proof.
  unfold lp. intros a b x y H. simpl in H.
  injection H as Hlen Hrest.
  exact (app_split a b x y Hlen Hrest).
Qed.

Definition field := (bytes * bytes)%type.

Definition encode_field (f : field) : bytes := lp (fst f) ++ lp (snd f).

Fixpoint encode_fields (fs : list field) : bytes :=
  match fs with
  | []        => []
  | f :: rest => encode_field f ++ encode_fields rest
  end.

Lemma encode_field_nonempty : forall f, encode_field f <> [].
Proof. intros [l v]. unfold encode_field, lp. simpl. discriminate. Qed.

Lemma encode_field_app_inj :
  forall f1 f2 x y,
    encode_field f1 ++ x = encode_field f2 ++ y -> f1 = f2 /\ x = y.
Proof.
  intros [l1 v1] [l2 v2] x y H.
  unfold encode_field in H. cbn [fst snd] in H.
  rewrite <- !app_assoc in H.
  apply lp_app_inj in H as [Hl Hrest].
  apply lp_app_inj in Hrest as [Hv Hxy].
  subst. auto.
Qed.

(* Lemma L2: distinct field sequences yield distinct encodings. *)
Theorem transcript_injective :
  forall fs1 fs2, encode_fields fs1 = encode_fields fs2 -> fs1 = fs2.
Proof.
  induction fs1 as [|f1 r1 IH]; intros [|f2 r2] H; cbn [encode_fields] in H.
  - reflexivity.
  - symmetry in H. apply app_eq_nil in H as [He _].
    exfalso. exact (encode_field_nonempty f2 He).
  - apply app_eq_nil in H as [He _].
    exfalso. exact (encode_field_nonempty f1 He).
  - apply encode_field_app_inj in H as [Hf Hr]. subst. f_equal. apply IH. exact Hr.
Qed.

(* ================================================================= *)
(*  Capability lattice (internal/capability)                         *)
(* ================================================================= *)
(*  Dot-separated capabilities as segment lists; a grant COVERS a      *)
(*  request iff it is a prefix (the dot-prefix covering). The granted   *)
(*  set's downward closure is the permitted set.                        *)

Definition cap := list nat.   (* segments, e.g. ["fs";"read"] as codes *)

Definition prefix (g r : cap) : Prop := exists s, r = g ++ s.

Definition covered (r : cap) (G : list cap) : Prop :=
  exists g, In g G /\ prefix g r.

(* A grant covers itself. *)
Lemma covered_self : forall g G, In g G -> covered g G.
Proof. intros g G Hin. exists g. split; [exact Hin | exists []; now rewrite app_nil_r]. Qed.

(* T4 monotonicity: more grants never remove a permission. *)
Theorem covered_monotone :
  forall r G G', incl G G' -> covered r G -> covered r G'.
Proof.
  intros r G G' Hincl [g [Hin Hp]].
  exists g. split; [apply Hincl; exact Hin | exact Hp].
Qed.

(* Attenuation (multi-hop): a delegate holding a subset grants no more. *)
Corollary covered_attenuation :
  forall r G' G, incl G' G -> covered r G' -> covered r G.
Proof. intros r G' G. apply covered_monotone. Qed.

(* Non-escalation / fail-closed: no covering grant => denied. *)
Theorem no_grant_denied :
  forall r G, (forall g, In g G -> ~ prefix g r) -> ~ covered r G.
Proof. intros r G Hno [g [Hin Hp]]. exact (Hno g Hin Hp). Qed.

(* Refinement closure: a broad grant permits all more-specific requests
   beneath it (granting "fs" permits "fs.read", "fs.read.x", ...). *)
Theorem covered_refine :
  forall r s G, covered r G -> covered (r ++ s) G.
Proof.
  intros r s G [g [Hin [t Ht]]].
  exists g. split; [exact Hin |].
  exists (t ++ s). subst r. now rewrite app_assoc.
Qed.
