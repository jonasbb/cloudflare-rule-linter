use wirefilter::{
    FunctionArgKind, FunctionArgs, FunctionDefinition, FunctionDefinitionContext, FunctionParam,
    FunctionParamError, GetType, LhsValue, ParserSettings, Type,
};

#[derive(Debug)]
pub(super) struct HasValue {}

impl FunctionDefinition for HasValue {
    fn check_param(
        &self,
        _: &ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        next_param: &FunctionParam<'_>,
        _: Option<&mut FunctionDefinitionContext>,
    ) -> Result<(), FunctionParamError> {
        match params.len() {
            0 => {
                next_param.arg_kind().expect(FunctionArgKind::Field)?;
                next_param.expect_val_type(
                    [
                        wirefilter::ExpectedType::Array,
                        wirefilter::ExpectedType::Map,
                    ]
                    .into_iter(),
                )?;
            }
            1 => {
                let collection_type = params
                    .next()
                    .expect("Length has been checked")
                    .get_type()
                    .next()
                    .expect("Checked for Map|Array before");
                next_param.expect_val_type(std::iter::once(collection_type.into()))?;
            }
            _ => unreachable!("Checked by arg_count"),
        }

        Ok(())
    }

    fn return_type(
        &self,
        _: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<&FunctionDefinitionContext>,
    ) -> Type {
        Type::Bool
    }

    fn arg_count(&self) -> (usize, Option<usize>) {
        (2, Some(0))
    }

    fn compile(
        &self,
        _: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        unimplemented!("compile has_key function")
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;

    #[test]
    fn test_has_value_array_bytes() {
        assert_parse(r#"has_value(http.request.headers.names, "X-My-Header")"#);
        assert_parse(r#"has_value(http.request.headers.names, http.request.uri.args.names[0])"#);
    }

    #[test]
    fn test_has_value_array_int() {
        assert_parse(r#"has_value(cf.bot_management.detection_ids, 123)"#);
    }

    #[test]
    fn test_has_value_extra_arg() {
        assert_parse_error(
            r#"has_value(http.request.headers.names, "x-my-header", "extra")"#,
            expect![[r#"
                Filter parsing error (1:54):
                has_value(http.request.headers.names, "x-my-header", "extra")
                                                                     ^^^^^^^^ invalid number of arguments
            "#]],
        );
    }

    #[test]
    fn test_has_value_mismatch_type() {
        assert_parse_error(
            r#"has_value(http.request.headers.names, 123)"#,
            expect![[r#"
                Filter parsing error (1:39):
                has_value(http.request.headers.names, 123)
                                                      ^^^ invalid type of argument #1: expected value of type Bytes, but got Int
            "#]],
        );
        assert_parse_error(
            r#"has_value(cf.bot_management.detection_ids, "Foo")"#,
            expect![[r#"
                Filter parsing error (1:44):
                has_value(cf.bot_management.detection_ids, "Foo")
                                                           ^^^^^ invalid type of argument #1: expected value of type Int, but got Bytes
            "#]],
        );
    }
}
