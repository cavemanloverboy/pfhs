use bls_signatures::Serialize;
use borsh::BorshSerialize;

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
#[repr(transparent)]
pub struct Signature(pub bls_signatures::Signature);

pub fn aggregate_signatures(
    sigs: &[Signature],
) -> Result<Signature, bls_signatures::Error> {
    bls_signatures::aggregate(
        // SAFETY: transparent type
        unsafe { core::mem::transmute(sigs) },
    )
    .map(Signature)
}

impl std::hash::Hash for Signature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // TODO: This allocates which is sad
        self.0.as_bytes().hash(state);
    }
}

impl std::ops::Deref for Signature {
    type Target = bls_signatures::Signature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl BorshSerialize for Signature {
    fn serialize<W: std::io::prelude::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        // TODO: This allocates which is sad
        writer.write(&self.0.as_bytes())?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
#[repr(transparent)]
pub struct PublicKey(pub bls_signatures::PublicKey);

impl std::hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // TODO: This allocates which is sad
        self.0.as_bytes().hash(state);
    }
}

impl std::ops::Deref for PublicKey {
    type Target = bls_signatures::PublicKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: std::io::prelude::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        // TODO: This allocates which is sad
        writer.write(&self.0.as_bytes())?;
        Ok(())
    }
}
