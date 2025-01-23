using AltShare.Models;
using AltShare.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AltShare.Controllers
{
    [ApiController]
    [Route("/account")]
    public class AccountController : Controller
    {
        private readonly SharedAccountService _sharedService;

        public AccountController(SharedAccountService SharedService)
        {
            _sharedService = SharedService;
        }

        [Authorize]
        [HttpPost("upload")]
        public IActionResult UploadAccount([FromBody] SharedAccount account)
        {
            _sharedService.Create(account);
            return Ok();
        }
    }
}
