//! Portable exports on wasmtime: any export function of a device called by name with
//! [`Value`]s ([`wasmnet_core::ControlCall::invocation`]), the same mechanism the browser backend
//! calls every export with.
//!
//! Every device's actor ends its list of control handlers with [`Exports`]: a call no typed
//! handler took (commands, reconfiguration, an extension's export adapter) is converted to
//! dynamic `Val`s by the function's own types and called inside the device's live event loop.
//! A dynamic `Val` costs a host allocation per list element, so an export that moves large byte
//! strings gets a typed adapter instead (`portable_adapter!` with a world that exports the
//! interface): the adapter's handler comes first and takes the call.

use std::collections::BTreeMap;

use wasmnet_core::ext::ControlCall;
use wasmnet_core::value::Value;
use wasmtime::Store;
use wasmtime::component::types::{ComponentItem, Type};
use wasmtime::component::{Accessor, Component, Func, Instance, Val};

use crate::extension::{ControlFuture, ControlHandler};
use crate::portable::{invoked, now};
use crate::wasi::HostState;

/// A device's export functions by interface (without a version), then by name.
pub(crate) struct Exports {
    funcs: BTreeMap<String, BTreeMap<String, Func>>,
}

impl Exports {
    /// Every function of every interface `instance` exports.
    pub(crate) fn find(
        component: &Component,
        store: &mut Store<HostState>,
        instance: &Instance,
    ) -> Self {
        let mut funcs: BTreeMap<String, BTreeMap<String, Func>> = BTreeMap::new();
        let ty = component.component_type();
        for (iname, item) in ty.exports(component.engine()) {
            let ComponentItem::ComponentInstance(inst) = item.ty else {
                continue;
            };
            if !iname.contains(':') {
                continue;
            }
            let Some(iidx) = instance.get_export_index(&mut *store, None, iname) else {
                continue;
            };
            for (fname, item) in inst.exports(component.engine()) {
                if !matches!(item.ty, ComponentItem::ComponentFunc(_)) {
                    continue;
                }
                let func = instance
                    .get_export_index(&mut *store, Some(&iidx), fname)
                    .and_then(|i| instance.get_func(&mut *store, i));
                if let Some(func) = func {
                    funcs
                        .entry(wasmnet_core::export::unversioned(iname).to_owned())
                        .or_default()
                        .insert(fname.to_owned(), func);
                }
            }
        }
        Self { funcs }
    }
}

impl ControlHandler for Exports {
    fn serve<'a>(
        &'a self,
        acc: &'a Accessor<HostState>,
        call: Box<dyn ControlCall>,
    ) -> Result<ControlFuture<'a>, Box<dyn ControlCall>> {
        // Checked by name first: a call this device has no function for goes back untouched.
        let Some(func) = call
            .target()
            .and_then(|(i, f)| self.funcs.get(i).and_then(|fs| fs.get(f)))
            .copied()
        else {
            return Err(call);
        };
        let mut call = call;
        let Some(invocation) = call.invocation(now(acc)) else {
            return Err(call);
        };
        Ok(Box::pin(async move {
            let ty = acc.with(|s| func.ty(s));
            let params: Vec<Type> = ty.params().map(|(_, t)| t).collect();
            let result = ty.results().next();
            if params.len() != invocation.args.len() {
                return Err(wasmtime::format_err!(
                    "{}#{}: {} arguments, it takes {}",
                    invocation.interface,
                    invocation.function,
                    invocation.args.len(),
                    params.len()
                ));
            }
            let args = invocation
                .args
                .into_iter()
                .zip(&params)
                .map(|(v, t)| to_val(v, t))
                .collect::<Result<Vec<Val>, String>>()
                .map_err(|e| {
                    wasmtime::format_err!("{}#{}: {e}", invocation.interface, invocation.function)
                })?;
            let mut results = vec![Val::Bool(false); usize::from(result.is_some())];
            func.call_concurrent(acc, &args, &mut results).await?;
            let answer = match (results.pop(), result) {
                (Some(Val::Result(r)), Some(Type::Result(rt))) => match r {
                    Ok(v) => Ok(lift(v, rt.ok())),
                    Err(v) => Err(lift(v, rt.err())),
                },
                (Some(v), Some(t)) => Ok(to_value(&v, &t)),
                _ => Ok(Value::None),
            };
            invoked(acc, call, answer);
            Ok(())
        }))
    }
}

fn lift(v: Option<Box<Val>>, t: Option<Type>) -> Value {
    v.zip(t).map_or(Value::None, |(v, t)| to_value(&v, &t))
}

/// A value as calls carry it ([`Value`]) in the shapes the browser backend answers with (jco's):
/// an option's value bare, `list<u8>` as bytes, a tuple as a list.
pub(crate) fn to_value(v: &Val, t: &Type) -> Value {
    match (v, t) {
        (Val::Option(None), _) => Value::None,
        (Val::Option(Some(v)), Type::Option(o)) => to_value(v, &o.ty()),
        (Val::Bool(b), _) => Value::Bool(*b),
        (Val::U8(n), _) => Value::U32(u32::from(*n)),
        (Val::U16(n), _) => Value::U32(u32::from(*n)),
        (Val::U32(n), _) => Value::U32(*n),
        (Val::U64(n), _) => Value::U64(*n),
        (Val::String(s), _) => Value::Str(s.clone()),
        (Val::List(items), Type::List(l)) if l.ty() == Type::U8 => Value::Bytes(
            items
                .iter()
                .map(|b| match b {
                    Val::U8(b) => *b,
                    _ => 0,
                })
                .collect(),
        ),
        (Val::List(items), Type::List(l)) => {
            Value::List(items.iter().map(|i| to_value(i, &l.ty())).collect())
        }
        (Val::Tuple(items), Type::Tuple(tt)) => Value::List(
            items
                .iter()
                .zip(tt.types())
                .map(|(i, t)| to_value(i, &t))
                .collect(),
        ),
        (Val::Record(fields), Type::Record(r)) => Value::Record(
            fields
                .iter()
                .zip(r.fields())
                .map(|((name, v), f)| (name.clone(), to_value(v, &f.ty)))
                .collect(),
        ),
        (Val::Variant(tag, payload), Type::Variant(var)) => {
            let ty = var.cases().find(|c| c.name == tag).and_then(|c| c.ty);
            Value::Variant(
                tag.clone(),
                payload
                    .as_deref()
                    .zip(ty)
                    .map(|(p, t)| Box::new(to_value(p, &t))),
            )
        }
        (Val::Result(r), Type::Result(rt)) => match r {
            Ok(v) => Value::Variant("ok".into(), Some(Box::new(lift(v.clone(), rt.ok())))),
            Err(v) => Value::Variant("err".into(), Some(Box::new(lift(v.clone(), rt.err())))),
        },
        (Val::Enum(name), _) => Value::Enum(name.clone()),
        // What the browser boundary does not carry (signed integers, floats, chars, flags,
        // resources) crosses as its text.
        (other, _) => Value::Str(format!("{other:?}")),
    }
}

/// A [`Value`] in the parameter's own type.
pub(crate) fn to_val(v: Value, t: &Type) -> Result<Val, String> {
    Ok(match (v, t) {
        (Value::None, Type::Option(_)) => Val::Option(None),
        (Value::Some(v), Type::Option(o)) => Val::Option(Some(Box::new(to_val(*v, &o.ty())?))),
        // An option's value may come bare (jco's shape).
        (v, Type::Option(o)) => Val::Option(Some(Box::new(to_val(v, &o.ty())?))),
        (Value::Bool(b), Type::Bool) => Val::Bool(b),
        (Value::U32(n), Type::U8) => Val::U8(u8::try_from(n).map_err(|e| e.to_string())?),
        (Value::U32(n), Type::U16) => Val::U16(u16::try_from(n).map_err(|e| e.to_string())?),
        (Value::U32(n), Type::U32) => Val::U32(n),
        (Value::U32(n), Type::U64) => Val::U64(u64::from(n)),
        (Value::U64(n), Type::U64) => Val::U64(n),
        (Value::Str(s), Type::String) => Val::String(s),
        (Value::Bytes(b), Type::List(l)) if l.ty() == Type::U8 => {
            Val::List(b.into_iter().map(Val::U8).collect())
        }
        (Value::List(items), Type::List(l)) => Val::List(
            items
                .into_iter()
                .map(|i| to_val(i, &l.ty()))
                .collect::<Result<_, _>>()?,
        ),
        (Value::Tuple(items) | Value::List(items), Type::Tuple(tt)) => Val::Tuple(
            items
                .into_iter()
                .zip(tt.types())
                .map(|(i, t)| to_val(i, &t))
                .collect::<Result<_, _>>()?,
        ),
        (Value::Record(fields), Type::Record(r)) => {
            let mut fields: BTreeMap<String, Value> = fields.into_iter().collect();
            Val::Record(
                r.fields()
                    .map(|f| {
                        let v = fields
                            .remove(f.name)
                            .ok_or_else(|| format!("no field `{}`", f.name))?;
                        Ok((f.name.to_owned(), to_val(v, &f.ty)?))
                    })
                    .collect::<Result<_, String>>()?,
            )
        }
        (Value::Variant(tag, payload), Type::Result(r)) => {
            let ok = tag == "ok";
            let ty = if ok { r.ok() } else { r.err() };
            let payload = match payload.zip(ty) {
                Some((p, t)) => Some(Box::new(to_val(*p, &t)?)),
                None => None,
            };
            Val::Result(if ok { Ok(payload) } else { Err(payload) })
        }
        (Value::Variant(tag, payload), Type::Variant(var)) => {
            let case = var
                .cases()
                .find(|c| c.name == tag)
                .ok_or_else(|| format!("no case `{tag}`"))?;
            let payload = match payload.zip(case.ty) {
                Some((p, t)) => Some(Box::new(to_val(*p, &t)?)),
                None => None,
            };
            Val::Variant(tag, payload)
        }
        (Value::Enum(name) | Value::Str(name), Type::Enum(_)) => Val::Enum(name),
        (v, t) => return Err(format!("{v:?} does not fit {t:?}")),
    })
}
