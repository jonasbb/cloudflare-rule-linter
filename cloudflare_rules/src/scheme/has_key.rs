use wirefilter::{
    FunctionArgKind, FunctionArgs, FunctionDefinition, FunctionDefinitionContext, FunctionParam,
    FunctionParamError, LhsValue, ParserSettings, Type,
};

#[derive(Debug)]
pub(super) struct HasKey {}

impl FunctionDefinition for HasKey {
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
                next_param.expect_val_type(std::iter::once(wirefilter::ExpectedType::Map))?;
            }
            _ => {
                next_param.expect_val_type(std::iter::once(Type::Bytes.into()))?;
            }
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
    fn test_has_key() {
        assert_parse(r#"has_key(http.request.headers, "x-my-header")"#);
        assert_parse(r#"has_key(http.request.headers, lower(http.request.uri.args.names[0]))"#);
    }

    #[test]
    fn test_has_key_extra_arg() {
        assert_parse_error(
            r#"has_key(http.request.headers, "x-my-header", "extra")"#,
            expect![[r#"
                Filter parsing error (1:46):
                has_key(http.request.headers, "x-my-header", "extra")
                                                             ^^^^^^^^ invalid number of arguments
            "#]],
        );
    }
}
