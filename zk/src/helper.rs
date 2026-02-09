use ark_bn254::Fr;
use ark_bn254::G1Projective as C;
use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use merlin::Transcript;

pub fn transcript_append_point(transcript: &mut Transcript, label: &'static [u8], p: &C) {
    let mut buf = Vec::new();
    p.into_affine().serialize_compressed(&mut buf).unwrap();
    transcript.append_message(label, &buf);
}

pub fn transcript_append_element(transcript: &mut Transcript, label: &'static [u8], e: &Fr) {
    let mut buf = Vec::new();
    e.serialize_compressed(&mut buf).unwrap();
    transcript.append_message(label, &buf);
}
