// This file is @generated by prost-build.
/// `Any` contains an arbitrary serialized protocol buffer message along with a
/// URL that describes the type of the serialized message.
///
/// Protobuf library provides support to pack/unpack Any values in the form
/// of utility functions or additional generated methods of the Any type.
///
/// Example 1: Pack and unpack a message in C++.
///
///      Foo foo = ...;
///      Any any;
///      any.PackFrom(foo);
///      ...
///      if (any.UnpackTo(&foo)) {
///        ...
///      }
///
/// Example 2: Pack and unpack a message in Java.
///
///      Foo foo = ...;
///      Any any = Any.pack(foo);
///      ...
///      if (any.is(Foo.class)) {
///        foo = any.unpack(Foo.class);
///      }
///      // or ...
///      if (any.isSameTypeAs(Foo.getDefaultInstance())) {
///        foo = any.unpack(Foo.getDefaultInstance());
///      }
///
///   Example 3: Pack and unpack a message in Python.
///
///      foo = Foo(...)
///      any = Any()
///      any.Pack(foo)
///      ...
///      if any.Is(Foo.DESCRIPTOR):
///        any.Unpack(foo)
///        ...
///
///   Example 4: Pack and unpack a message in Go
///
///       foo := &pb.Foo{...}
///       any, err := anypb.New(foo)
///       if err != nil {
///         ...
///       }
///       ...
///       foo := &pb.Foo{}
///       if err := any.UnmarshalTo(foo); err != nil {
///         ...
///       }
///
/// The pack methods provided by protobuf library will by default use
/// 'type.googleapis.com/full.type.name' as the type URL and the unpack
/// methods only use the fully qualified type name after the last '/'
/// in the type URL, for example "foo.bar.com/x/y.z" will yield type
/// name "y.z".
///
/// JSON
/// ====
/// The JSON representation of an `Any` value uses the regular
/// representation of the deserialized, embedded message, with an
/// additional field `@type` which contains the type URL. Example:
///
///      package google.profile;
///      message Person {
///        string first_name = 1;
///        string last_name = 2;
///      }
///
///      {
///        "@type": "type.googleapis.com/google.profile.Person",
///        "firstName": <string>,
///        "lastName": <string>
///      }
///
/// If the embedded message type is well-known and has a custom JSON
/// representation, that representation will be embedded adding a field
/// `value` which holds the custom JSON in addition to the `@type`
/// field. Example (for message [google.protobuf.Duration][]):
///
///      {
///        "@type": "type.googleapis.com/google.protobuf.Duration",
///        "value": "1.212s"
///      }
///
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Any {
    /// A URL/resource name that uniquely identifies the type of the serialized
    /// protocol buffer message. This string must contain at least
    /// one "/" character. The last segment of the URL's path must represent
    /// the fully qualified name of the type (as in
    /// `path/google.protobuf.Duration`). The name should be in a canonical form
    /// (e.g., leading "." is not accepted).
    ///
    /// In practice, teams usually precompile into the binary all types that they
    /// expect it to use in the context of Any. However, for URLs which use the
    /// scheme `http`, `https`, or no scheme, one can optionally set up a type
    /// server that maps type URLs to message definitions as follows:
    ///
    /// * If no scheme is provided, `https` is assumed.
    /// * An HTTP GET on the URL must yield a [google.protobuf.Type][]
    ///    value in binary format, or produce an error.
    /// * Applications are allowed to cache lookup results based on the
    ///    URL, or have them precompiled into a binary to avoid any
    ///    lookup. Therefore, binary compatibility needs to be preserved
    ///    on changes to types. (Use versioned type names to manage
    ///    breaking changes.)
    ///
    /// Note: this functionality is not currently available in the official
    /// protobuf release, and it is not used for type URLs beginning with
    /// type.googleapis.com. As of May 2023, there are no widely used type server
    /// implementations and no plans to implement one.
    ///
    /// Schemes other than `http`, `https` (or the empty scheme) might be
    /// used with implementation specific semantics.
    ///
    #[prost(string, tag = "1")]
    pub type_url: ::prost::alloc::string::String,
    /// Must be a valid serialized protocol buffer of the above specified type.
    #[prost(bytes = "vec", tag = "2")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}

# [allow (dead_code)] const IMPL_MESSAGE_SERDE_FOR_ANY : () = { use :: prost_wkt :: typetag ; # [typetag :: serde (name = "type.googleapis.com/google.protobuf.Any")] impl :: prost_wkt :: MessageSerde for Any { fn package_name (& self) -> & 'static str { "google.protobuf" } fn message_name (& self) -> & 'static str { "Any" } fn type_url (& self) -> & 'static str { "type.googleapis.com/google.protobuf.Any" } fn new_instance (& self , data : Vec < u8 >) -> :: std :: result :: Result < Box < dyn :: prost_wkt :: MessageSerde > , :: prost :: DecodeError > { let mut target = Self :: default () ; :: prost :: Message :: merge (& mut target , data . as_slice ()) ? ; let erased : :: std :: boxed :: Box < dyn :: prost_wkt :: MessageSerde > = :: std :: boxed :: Box :: new (target) ; Ok (erased) } fn try_encoded (& self) -> :: std :: result :: Result < :: std :: vec :: Vec < u8 > , :: prost :: EncodeError > { let mut buf = :: std :: vec :: Vec :: with_capacity (:: prost :: Message :: encoded_len (self)) ; :: prost :: Message :: encode (self , & mut buf) ? ; Ok (buf) } } :: prost_wkt :: inventory :: submit ! { :: prost_wkt :: MessageSerdeDecoderEntry { type_url : "type.googleapis.com/google.protobuf.Any" , decoder : | buf : & [u8] | { let msg : Any = :: prost :: Message :: decode (buf) ? ; Ok (:: std :: boxed :: Box :: new (msg)) } } } impl :: prost :: Name for Any { const PACKAGE : & 'static str = "google.protobuf" ; const NAME : & 'static str = "Any" ; fn type_url () -> String { "type.googleapis.com/google.protobuf.Any" . to_string () } } } ;
