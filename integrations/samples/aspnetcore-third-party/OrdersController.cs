using Microsoft.AspNetCore.Mvc;
using Sentomaru.AspNetCore;

namespace ThirdPartyApi;

[ApiController]
[Route("pedidos")]
public sealed class OrdersController(OrderStore store) : ControllerBase
{
    // guide:begin protected-action
    [HttpPost("{id}/concluir")]
    [SentomaruIntegrity("concluir_pedido")] // ZeroTrust (default): runs only on an allow verdict
    public IActionResult Complete(string id)
    {
        store.Complete(id);
        return Ok(new { id, status = "concluido" });
    }
    // guide:end protected-action

    // guide:begin replay-action
    [HttpPost("{id}/pagar")]
    [SentomaruIntegrity("pagar_pedido", AllowOperationReplay = true)]
    public IActionResult Pay(string id)
    {
        var operationId = HttpContext.Items[SentomaruIntegrityAttribute.OperationIdItem] as string;
        var firstAdmission = HttpContext.Items[SentomaruIntegrityAttribute.FirstAdmissionItem] as bool?;
        if (operationId is not null && firstAdmission == false)
        {
            // A retry of an operation already admitted: return what was stored, never charge again. The charge and
            // its receipt are written in one transaction (OrderStore.Charge), so no receipt means no charge: the first
            // attempt is still running, or it died before committing. Neither may be charged again here (the first
            // could still commit), so the app gets 409 and asks later; after a crash that lasts until the id expires
            // (24 h) or the app starts a new operation with a new id.
            return store.ReceiptFor(operationId) is { } stored
                ? Ok(new { id, receipt = stored })
                : Conflict(new { code = "operation-in-progress" });
        }
        return Ok(new { id, receipt = store.Charge(id, operationId) });
    }
    // guide:end replay-action

    // guide:begin observe-action
    [HttpGet("{id}")]
    [SentomaruIntegrity("consultar_pedido", DeviceAssuranceLevel.Observe)] // telemetry only: NOT protected
    public IActionResult Get(string id) => Ok(new { id });
    // guide:end observe-action
}
